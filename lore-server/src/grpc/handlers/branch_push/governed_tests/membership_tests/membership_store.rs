// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_storage::Fragment;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
use lore_storage::StoreError;
use lore_storage::StoreGetData;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;

use super::*;

pub(super) struct MembershipStore {
    pub inner: Arc<dyn ImmutableStore>,
    pub coordinator: Arc<PostgresFragmentCoordinator>,
    pub repository: [u8; 16],
    pub addresses: StdMutex<Vec<Address>>,
    pub queried: StdMutex<std::collections::BTreeSet<Address>>,
    pub pause_read: std::sync::atomic::AtomicBool,
    pub read_reached: tokio::sync::Notify,
    pub read_resume: tokio::sync::Notify,
}

impl MembershipStore {
    pub async fn upload_fresh(self: Arc<Self>) {
        let bytes = bytes::Bytes::copy_from_slice(&rand::random::<[u8; 16]>());
        let fragment = Fragment {
            flags: 0,
            size_payload: 16,
            size_content: 16,
        };
        let address = Address {
            hash: lore_storage::hash::hash_fragment(fragment, &bytes).unwrap(),
            context: rand::random(),
        };
        self.clone()
            .put(
                self.repository.into(),
                address,
                fragment,
                Some(bytes),
                false,
            )
            .await
            .unwrap();
    }

    pub fn for_repository(&self, repository: [u8; 16]) -> Self {
        Self {
            inner: self.inner.clone(),
            coordinator: self.coordinator.clone(),
            repository,
            addresses: Default::default(),
            queried: Default::default(),
            pause_read: std::sync::atomic::AtomicBool::new(false),
            read_reached: Default::default(),
            read_resume: Default::default(),
        }
    }
    pub async fn record(&self, address: Address) -> Result<(), StoreError> {
        let hash = address.hash.as_ref();
        match self
            .coordinator
            .begin_stage(hash)
            .await
            .map_err(|e| StoreError::internal(e.to_string()))?
        {
            BeginOutcome::Admitted(intent) => {
                let manifest = FragmentManifest {
                    authority: EpochAuthority::Staged,
                    object_key: intent.object_key.clone(),
                    manifest_id: hash.to_vec(),
                    decoded_hash: hash.to_vec(),
                    size_payload: 1,
                    size_content: 1,
                    payload_flags: 0,
                };
                assert_eq!(
                    self.coordinator
                        .commit_staged(&intent, IoObservation::Valid(manifest))
                        .await
                        .unwrap(),
                    CommitVerdict::Published
                );
            }
            BeginOutcome::AlreadyReadable(_) => {}
            other => panic!("fixture publication refused: {other:?}"),
        }
        assert_eq!(
            self.coordinator
                .create_association(hash, &self.repository, address.context.as_ref())
                .await
                .unwrap(),
            CommitVerdict::Published
        );
        self.addresses.lock().unwrap().push(address);
        Ok(())
    }
}
#[async_trait::async_trait]
impl ImmutableStore for MembershipStore {
    async fn query(
        self: Arc<Self>,
        partition: Partition,
        addresses: &[Address],
        results: &mut [StoreMatchResult],
    ) -> Result<(), StoreError> {
        self.queried
            .lock()
            .unwrap()
            .extend(addresses.iter().copied());
        self.inner
            .clone()
            .query(partition, addresses, results)
            .await?;
        for (address, result) in addresses.iter().zip(results.iter_mut()) {
            let found = self
                .coordinator
                .resolve(
                    &self.repository,
                    address.context.as_ref(),
                    &[address.hash.as_ref().to_vec()],
                )
                .await
                .map_err(|e| StoreError::internal(e.to_string()))?;
            if !matches!(found[0].verdict, FragmentVerdict::Readable { .. }) {
                *result = StoreMatchResult::default();
            }
        }
        Ok(())
    }

    async fn get_metadata(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        self.inner.clone().get_metadata(partition, address).await
    }

    async fn get(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        if self
            .pause_read
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.read_reached.notify_one();
            self.read_resume.notified().await;
        }
        self.inner.clone().get(partition, address).await
    }

    async fn put(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
        force: bool,
    ) -> Result<(), StoreError> {
        self.record(address).await?;
        self.inner
            .clone()
            .put(partition, address, fragment, payload, force)
            .await
    }

    async fn obliterate(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        stats: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        self.inner
            .clone()
            .obliterate(partition, address, stats)
            .await
    }

    async fn evict(
        self: Arc<Self>,
        max_capacity: usize,
        sync_data: bool,
        sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<usize, StoreError> {
        self.inner
            .clone()
            .evict(max_capacity, sync_data, sink)
            .await
    }

    async fn compact(
        self: Arc<Self>,
        max_size: usize,
        at: Option<usize>,
        sync_data: bool,
        sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<Option<usize>, StoreError> {
        self.inner
            .clone()
            .compact(max_size, at, sync_data, sink)
            .await
    }

    async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
        self.inner.clone().compact_resume_at().await
    }

    async fn compact_stop(self: Arc<Self>) {
        self.inner.clone().compact_stop().await
    }

    fn max_query_batch(&self) -> Option<usize> {
        self.inner.max_query_batch()
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.inner.clone().flush(sync_data).await
    }

    async fn verify(self: Arc<Self>, heal: bool) -> Result<(), StoreError> {
        self.inner.clone().verify(heal).await
    }

    async fn copy(
        self: Arc<Self>,
        source_partition: Partition,
        source_address: Address,
        destination_partition: Partition,
        destination_context: Context,
        durable: bool,
    ) -> Result<(), StoreError> {
        self.inner
            .clone()
            .copy(
                source_partition,
                source_address,
                destination_partition,
                destination_context,
                durable,
            )
            .await
    }
}
