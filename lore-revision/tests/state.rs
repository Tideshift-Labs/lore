// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#[ctor::ctor]
fn init_test_policies() {
    let _ = lore_storage::STORE_RETRY_ATTEMPTS.set(1);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Test fixture writes; not subject to repository write-token discipline.

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::RwLock;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    use async_trait::async_trait;
    use bytes::Bytes;
    use lore_base::error::NoRemote;
    use lore_base::error::SlowDown;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::runtime::runtime;
    use lore_base::types::Address;
    use lore_base::types::CloneHeapAlloc;
    use lore_base::types::Context;
    use lore_base::types::Fragment;
    use lore_base::types::FragmentFlags;
    use lore_base::types::FragmentReference;
    use lore_base::types::Hash;
    use lore_base::types::Partition;
    use lore_base::types::ZeroHeapAlloc;
    use lore_revision::immutable;
    use lore_revision::node::*;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryFormat;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::state::State;
    use lore_revision::state::StateData;
    use lore_revision::state::collect_new_fragments;
    use lore_storage::ImmutableStore;
    use lore_storage::StoreError;
    use lore_storage::StoreMatch;
    use lore_storage::StoreObliterateStats;
    use lore_storage::StoreQueryResult;
    use lore_storage::hash::hash_string;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_storage::local::immutable_store::LocalImmutableStore;
    use lore_transport::ProtocolError;
    use zerocopy::IntoBytes;

    include!("helper.rs");

    #[test]
    fn size() {
        assert_eq!(
            std::mem::size_of::<StateData>(),
            320,
            "State data size is invalid"
        );
    }

    #[test]
    fn clone_block_data() {
        // Create a node block data with some random data
        let mut block = NodeBlockData::new_from_heap_zeroed();
        block.flags = NodeBlockFlags::Dirty.as_u32();
        block.node[100].flags = NodeFlags::Discarded.as_u32() as u16;
        block.node_count = 150;

        // Clone it
        let cloned = block.clone_on_heap();
        assert_ne!(cloned.as_bytes().as_ptr(), block.as_bytes().as_ptr());
        assert_eq!(cloned.as_bytes(), block.as_bytes());
    }

    #[tokio::test]
    async fn collect_new_name_fragments() {
        let (_immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");
        let repository_id = Context::from(uuid::Uuid::now_v7());

        #[allow(clippy::disallowed_methods)]
        runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                let tempdir = generate_tempdir();
                let path = tempdir.to_path_buf();

                // Create an explicit immutable store to access some test functions
                let immutable_store = LocalImmutableStore::new(
                    None,
                    lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
                )
                .await
                .expect("Failed to create store");

                let write_token =
                    lore_revision::repository::RepositoryWriteToken::acquire(path.as_path()).await;
                let repository = Arc::new(
                    RepositoryContext::new(
                        Some(path.clone()),
                        immutable_store.clone(),
                        mutable_store.clone(),
                        repository_id.into(),
                        lore_revision::instance::InstanceId::default(),
                        Err(ProtocolError::from(NoRemote)),
                        Arc::default(),
                        RepositoryFormat::Lore,
                    )
                    .with_write_token(write_token.share()),
                );

                let state_from = Arc::new(State::new());

                let name = "test-node";
                let node = Node {
                    name_hash: hash_string(name),
                    ..Default::default()
                };
                state_from
                    .node_add(repository.clone(), ROOT_NODE, node, "test-node")
                    .await
                    .expect("Failed to add node");
                let signature_from = state_from
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize from state");

                let state_to = State::deserialize(repository.clone(), signature_from)
                    .await
                    .expect("Failed to deserialize state");

                let _signature_to = state_to
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize to state");

                let fragments = collect_new_fragments(
                    repository.clone(),
                    state_from.clone(),
                    state_to.clone(),
                    true,
                )
                .await
                .expect("Failed to collect fragments");

                assert!(
                    fragments.is_empty(),
                    "Unmodified state does not yield empty collection of new fragments"
                );

                let other_name = "other-test-node";
                let other_node = Node {
                    name_hash: hash_string(other_name),
                    ..Default::default()
                };
                state_to
                    .node_add(repository.clone(), ROOT_NODE, other_node, other_name)
                    .await
                    .expect("Failed to add node");

                let signature_to = state_to
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize to state");

                let state_to = State::deserialize(repository.clone(), signature_to)
                    .await
                    .expect("Failed to deserialize state");

                let fragments = collect_new_fragments(
                    repository.clone(),
                    state_from.clone(),
                    state_to.clone(),
                    true,
                )
                .await
                .expect("Failed to collect fragments");

                assert!(
                    !fragments.is_empty(),
                    "Modified state yielded empty collection of new fragments"
                );

                let name_fragment = state_to
                    .block(repository.clone(), 0)
                    .await
                    .expect("Failed to access node block")
                    .read()
                    .raw()
                    .name_table;

                // Hack to mark all data as durably stored
                immutable_store.mark_all_as_durably_stored().await;

                let fragments = collect_new_fragments(
                    repository.clone(),
                    state_from.clone(),
                    state_to.clone(),
                    true,
                )
                .await
                .expect("Failed to collect fragments");

                assert!(
                    fragments.is_empty(),
                    "New fragments not empty after all data marked as durably stored"
                );

                // Hack to mark all data as durably stored
                let name_address = Address::zero_context_hash(name_fragment);
                immutable_store
                    .mark_as_not_durably_stored(repository.id, name_address)
                    .await;

                let fragments = collect_new_fragments(
                    repository.clone(),
                    state_from.clone(),
                    state_to.clone(),
                    true,
                )
                .await
                .expect("Failed to collect fragments");

                assert!(
                    fragments.contains(&name_address),
                    "Name table not collected as new fragment after marked as not durably stored"
                );
            }))
            .await
            .expect("Test task failed");
    }

    /// Wraps a real, in-memory [`LocalImmutableStore`] and lets a test inject a
    /// configured failure into `query()` and/or `get()` — the two calls
    /// `collect_new_addresses` (`lore_revision::state`) makes while walking
    /// fragments. Everything not configured to fail delegates straight through
    /// to the real store, so state construction (`node_add`/`serialize`/
    /// `deserialize`) behaves exactly as it would against the real thing; only
    /// the specific calls a test arms are affected.
    ///
    /// All fault switches default to "off" (pure delegation) so a test can
    /// build its fixture states first and arm the fault only once they're
    /// ready to exercise `collect_new_fragments`.
    struct FaultInjectingStore {
        inner: Arc<LocalImmutableStore>,
        slow_down_all_queries: AtomicBool,
        generic_fail_all_queries: AtomicBool,
        slow_down_query_addresses: RwLock<BTreeSet<Address>>,
        slow_down_get_addresses: RwLock<BTreeSet<Address>>,
    }

    impl FaultInjectingStore {
        fn wrapping(inner: Arc<LocalImmutableStore>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                slow_down_all_queries: AtomicBool::new(false),
                generic_fail_all_queries: AtomicBool::new(false),
                slow_down_query_addresses: RwLock::new(BTreeSet::new()),
                slow_down_get_addresses: RwLock::new(BTreeSet::new()),
            })
        }

        /// Every subsequent `query()` call returns `StoreError::SlowDown`.
        fn arm_slow_down_all_queries(&self) {
            self.slow_down_all_queries.store(true, Ordering::SeqCst);
        }

        /// Every subsequent `query()` call returns a generic (non-`SlowDown`)
        /// `StoreError`, simulating an ordinary store failure.
        fn arm_generic_fail_all_queries(&self) {
            self.generic_fail_all_queries.store(true, Ordering::SeqCst);
        }

        /// `query()` calls for this specific address return `StoreError::SlowDown`;
        /// every other address delegates normally.
        fn arm_slow_down_query_for(&self, address: Address) {
            self.slow_down_query_addresses
                .write()
                .unwrap()
                .insert(address);
        }

        /// `get()` calls for this specific address return `StoreError::SlowDown`;
        /// every other address delegates normally. This is the call
        /// `lore_storage::read::read_raw` makes (via `immutable::load_raw`) when
        /// loading a fragmented payload's own content to read its child
        /// `FragmentReference` list — distinct from `query()`, which is what
        /// `collect_new_addresses` calls directly on each address it walks.
        fn arm_slow_down_get_for(&self, address: Address) {
            self.slow_down_get_addresses
                .write()
                .unwrap()
                .insert(address);
        }
    }

    #[async_trait]
    impl ImmutableStore for FaultInjectingStore {
        async fn exist(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            match_requested: StoreMatch,
        ) -> Result<StoreMatch, StoreError> {
            self.inner
                .clone()
                .exist(partition, address, match_requested)
                .await
        }

        async fn exist_batch(
            self: Arc<Self>,
            partition: Partition,
            addresses: &[Address],
            match_requested: StoreMatch,
        ) -> Result<Vec<StoreMatch>, StoreError> {
            self.inner
                .clone()
                .exist_batch(partition, addresses, match_requested)
                .await
        }

        async fn query(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            match_requested: StoreMatch,
        ) -> Result<StoreQueryResult, StoreError> {
            if self.slow_down_all_queries.load(Ordering::SeqCst)
                || self
                    .slow_down_query_addresses
                    .read()
                    .unwrap()
                    .contains(&address)
            {
                return Err(StoreError::from(SlowDown));
            }
            if self.generic_fail_all_queries.load(Ordering::SeqCst) {
                return Err(StoreError::internal(
                    "Simulated generic store failure (not SlowDown)",
                ));
            }
            self.inner
                .clone()
                .query(partition, address, match_requested)
                .await
        }

        async fn get_metadata(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<StoreQueryResult, StoreError> {
            self.inner.clone().get_metadata(partition, address).await
        }

        async fn get(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            match_required: StoreMatch,
        ) -> Result<(Fragment, Bytes), StoreError> {
            if self
                .slow_down_get_addresses
                .read()
                .unwrap()
                .contains(&address)
            {
                return Err(StoreError::from(SlowDown));
            }
            self.inner
                .clone()
                .get(partition, address, match_required)
                .await
        }

        async fn put(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            fragment: Fragment,
            payload: Option<Bytes>,
            force: bool,
        ) -> Result<(), StoreError> {
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
    }

    /// Builds a two-node-block diff (`state_from` has `test-node`, `state_to`
    /// additionally has `other-test-node`) against a [`FaultInjectingStore`],
    /// runs `body` with the fully-built repository/states/store once
    /// construction has completed normally, and returns whatever `body`
    /// returns. Mirrors the fixture shape of `collect_new_name_fragments`
    /// above, factored out so each fault-injection test only has to describe
    /// which call it arms and what it expects.
    async fn with_slow_down_fixture<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Arc<RepositoryContext>, Arc<State>, Arc<State>, Arc<FaultInjectingStore>) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = T> + Send,
        T: Send + 'static,
    {
        let (_immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");
        let repository_id = Context::from(uuid::Uuid::now_v7());

        #[allow(clippy::disallowed_methods)]
        runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                let tempdir = generate_tempdir();
                let path = tempdir.to_path_buf();

                let real_store = LocalImmutableStore::new(None, ImmutableStoreSettings::default())
                    .await
                    .expect("Failed to create store");
                let fault_store = FaultInjectingStore::wrapping(real_store);

                let write_token = RepositoryWriteToken::acquire(path.as_path()).await;
                let repository = Arc::new(
                    RepositoryContext::new(
                        Some(path.clone()),
                        fault_store.clone(),
                        mutable_store.clone(),
                        repository_id.into(),
                        lore_revision::instance::InstanceId::default(),
                        Err(ProtocolError::from(NoRemote)),
                        Arc::default(),
                        RepositoryFormat::Lore,
                    )
                    .with_write_token(write_token.share()),
                );

                let state_from = Arc::new(State::new());
                let name = "test-node";
                let node = Node {
                    name_hash: hash_string(name),
                    ..Default::default()
                };
                state_from
                    .node_add(repository.clone(), ROOT_NODE, node, name)
                    .await
                    .expect("Failed to add node");
                let signature_from = state_from
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize from state");
                let state_to = State::deserialize(repository.clone(), signature_from)
                    .await
                    .expect("Failed to deserialize state");

                let other_name = "other-test-node";
                let other_node = Node {
                    name_hash: hash_string(other_name),
                    ..Default::default()
                };
                state_to
                    .node_add(repository.clone(), ROOT_NODE, other_node, other_name)
                    .await
                    .expect("Failed to add node");
                let signature_to = state_to
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize to state");
                let state_to = State::deserialize(repository.clone(), signature_to)
                    .await
                    .expect("Failed to deserialize state");

                // Fixture is fully built against a store behaving normally;
                // only now does the caller arm whichever fault it wants to
                // observe.
                body(repository, state_from, state_to, fault_store).await
            }))
            .await
            .expect("Test task failed")
    }

    #[tokio::test]
    async fn collect_new_fragments_propagates_slow_down_from_query() {
        with_slow_down_fixture(|repository, state_from, state_to, fault_store| async move {
            fault_store.arm_slow_down_all_queries();

            let result = collect_new_fragments(repository, state_from, state_to, true).await;

            let err = result.expect_err(
                "Expected collect_new_fragments to propagate a SlowDown rather than \
                 silently treat every fragment as new",
            );
            assert!(
                err.is_slow_down(),
                "Expected StateError::SlowDown, got: {err:?}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn collect_new_fragments_keeps_conservative_fallback_for_non_slow_down_query_error() {
        with_slow_down_fixture(|repository, state_from, state_to, fault_store| async move {
            // Compute the name-table address the same way
            // `collect_new_name_fragments` does, before arming the fault, so we
            // can assert the specific address the conservative fallback must
            // still report as new.
            let name_fragment = state_to
                .block(repository.clone(), 0)
                .await
                .expect("Failed to access node block")
                .read()
                .raw()
                .name_table;
            let name_address = Address::zero_context_hash(name_fragment);

            fault_store.arm_generic_fail_all_queries();

            let fragments = collect_new_fragments(repository, state_from, state_to, true)
                .await
                .expect(
                    "A non-SlowDown query error must not fail collect_new_fragments \
                     (the pre-existing conservative fallback must be preserved)",
                );

            assert!(
                fragments.contains(&name_address),
                "A fragment whose query() failed with a non-SlowDown error must \
                 still be reported as new (fail-safe, over-report path)"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn genuinely_absent_fragment_is_reported_new_without_hitting_error_path() {
        // Pins the assumption the SlowDown-narrowing relies on: `find()`
        // (lore-storage/src/local/immutable_store.rs) returns `Ok` with
        // `StoreMatch::MatchNone` for a hash it has never seen — genuine
        // absence is not an error at all, so it can never reach either the
        // `SlowDown` branch or the conservative-fallback branch added by this
        // change. Uses the real store directly (no fault injection) since the
        // behavior under test is the store's, not `collect_new_addresses`'s.
        let (_immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");
        let repository_id = Context::from(uuid::Uuid::now_v7());

        #[allow(clippy::disallowed_methods)]
        runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                let tempdir = generate_tempdir();
                let path = tempdir.to_path_buf();

                let real_store = LocalImmutableStore::new(None, ImmutableStoreSettings::default())
                    .await
                    .expect("Failed to create store");

                let write_token = RepositoryWriteToken::acquire(path.as_path()).await;
                let repository = Arc::new(
                    RepositoryContext::new(
                        Some(path.clone()),
                        real_store,
                        mutable_store.clone(),
                        repository_id.into(),
                        lore_revision::instance::InstanceId::default(),
                        Err(ProtocolError::from(NoRemote)),
                        Arc::default(),
                        RepositoryFormat::Lore,
                    )
                    .with_write_token(write_token.share()),
                );

                let state_from = Arc::new(State::new());
                let signature_from = state_from
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize from state");
                let state_to = State::deserialize(repository.clone(), signature_from)
                    .await
                    .expect("Failed to deserialize state");

                // A node whose backing fragment was never written anywhere:
                // `query()` for it must come back `Ok(MatchNone)`, not an error.
                let name = "brand-new-never-stored-node";
                let node = Node {
                    name_hash: hash_string(name),
                    ..Default::default()
                };
                state_to
                    .node_add(repository.clone(), ROOT_NODE, node, name)
                    .await
                    .expect("Failed to add node");
                let signature_to = state_to
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize to state");
                let state_to = State::deserialize(repository.clone(), signature_to)
                    .await
                    .expect("Failed to deserialize state");

                let fragments = collect_new_fragments(repository, state_from, state_to, true)
                    .await
                    .expect(
                        "Genuine absence must not surface as an error from \
                             collect_new_fragments",
                    );

                assert!(
                    !fragments.is_empty(),
                    "A node added only in state_to must yield at least one new \
                     fragment when its backing content was never stored"
                );
            }))
            .await
            .expect("Test task failed");
    }

    /// Stores two raw chunks plus a `PayloadFragmented` fragment-reference list
    /// pointing at them, returning `(root_address, chunk_one_address,
    /// chunk_two_address, content_size)`. Mirrors `store_as_legacy_chunks` in
    /// the `is_file_modified_chunking_compat` module below, but returns both
    /// chunk addresses too so a test can target either specifically for fault
    /// injection.
    async fn store_two_chunk_fragmented_payload(
        repository: &Arc<RepositoryContext>,
        context: Context,
    ) -> (Address, Address, Address, u64) {
        let chunk_one: &[u8] = b"first-chunk-of-a-fragmented-payload------------";
        let chunk_two: &[u8] = b"second-chunk-of-a-fragmented-payload-----------";

        let mut refs = Vec::with_capacity(2);
        let mut offset: u64 = 0;
        let mut chunk_one_address = Address::default();
        let mut chunk_two_address = Address::default();
        for (index, chunk) in [chunk_one, chunk_two].into_iter().enumerate() {
            let chunk_bytes = Bytes::copy_from_slice(chunk);
            let hash = Hash::hash_buffer(chunk);
            let address = Address { hash, context };
            let fragment = Fragment {
                flags: FragmentFlags::PayloadStoredLocal.bits(),
                size_payload: chunk.len() as u32,
                size_content: chunk.len() as u64,
            };
            immutable::store_raw(
                repository.clone(),
                address,
                fragment,
                chunk_bytes,
                true,
                false,
            )
            .await
            .expect("Failed to store chunk fragment");

            if index == 0 {
                chunk_one_address = address;
            } else {
                chunk_two_address = address;
            }

            refs.push(FragmentReference {
                hash,
                offset_content: offset,
            });
            offset += chunk.len() as u64;
        }

        let content_size = offset;
        let list_bytes: Vec<u8> = refs.as_slice().as_bytes().to_vec();
        let list_bytes = Bytes::from(list_bytes);
        let list_hash = Hash::hash_buffer(list_bytes.as_ref());

        let root_address = Address {
            hash: list_hash,
            context,
        };
        let list_fragment = Fragment {
            flags: FragmentFlags::PayloadStoredLocal.bits()
                | FragmentFlags::PayloadFragmented.bits(),
            size_payload: list_bytes.len() as u32,
            size_content: content_size,
        };
        immutable::store_raw(
            repository.clone(),
            root_address,
            list_fragment,
            list_bytes,
            true,
            false,
        )
        .await
        .expect("Failed to store fragment list");

        (
            root_address,
            chunk_one_address,
            chunk_two_address,
            content_size,
        )
    }

    /// Builds `state_to` with a single new file node whose content is a
    /// two-chunk fragmented payload (`state_from` is an empty root), runs
    /// `body` once construction has completed normally against a
    /// [`FaultInjectingStore`], and returns whatever `body` returns.
    async fn with_fragmented_file_fixture<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(
                Arc<RepositoryContext>,
                Arc<State>,
                Arc<State>,
                Arc<FaultInjectingStore>,
                Address,
                Address,
                Address,
            ) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = T> + Send,
        T: Send + 'static,
    {
        let (_immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");
        let repository_id = Context::from(uuid::Uuid::now_v7());

        #[allow(clippy::disallowed_methods)]
        runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                let tempdir = generate_tempdir();
                let path = tempdir.to_path_buf();

                let real_store = LocalImmutableStore::new(None, ImmutableStoreSettings::default())
                    .await
                    .expect("Failed to create store");
                let fault_store = FaultInjectingStore::wrapping(real_store);

                let write_token = RepositoryWriteToken::acquire(path.as_path()).await;
                let repository = Arc::new(
                    RepositoryContext::new(
                        Some(path.clone()),
                        fault_store.clone(),
                        mutable_store.clone(),
                        repository_id.into(),
                        lore_revision::instance::InstanceId::default(),
                        Err(ProtocolError::from(NoRemote)),
                        Arc::default(),
                        RepositoryFormat::Lore,
                    )
                    .with_write_token(write_token.share()),
                );

                let state_from = Arc::new(State::new());
                let signature_from = state_from
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize from state");
                let state_to = State::deserialize(repository.clone(), signature_from)
                    .await
                    .expect("Failed to deserialize state");

                let content_context: Context = rand::random();
                let (root_address, chunk_one_address, chunk_two_address, content_size) =
                    store_two_chunk_fragmented_payload(&repository, content_context).await;

                let name = "fragmented-file.bin";
                let file_node = Node {
                    flags: NodeFlags::File.bits(),
                    size: content_size,
                    address: root_address,
                    name_hash: hash_string(name),
                    ..Default::default()
                };
                state_to
                    .node_add(repository.clone(), ROOT_NODE, file_node, name)
                    .await
                    .expect("Failed to add file node");
                let signature_to = state_to
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize to state");
                let state_to = State::deserialize(repository.clone(), signature_to)
                    .await
                    .expect("Failed to deserialize state");

                body(
                    repository,
                    state_from,
                    state_to,
                    fault_store,
                    root_address,
                    chunk_one_address,
                    chunk_two_address,
                )
                .await
            }))
            .await
            .expect("Test task failed")
    }

    #[tokio::test]
    async fn collect_new_fragments_propagates_slow_down_from_fragmented_payload_child() {
        // Swallow #3: a SlowDown while recursing into one of a fragmented
        // payload's children must propagate rather than silently dropping
        // that (and every sibling) child from the result.
        with_fragmented_file_fixture(
            |repository,
             state_from,
             state_to,
             fault_store,
             _root_address,
             _chunk_one_address,
             chunk_two_address| async move {
                fault_store.arm_slow_down_query_for(chunk_two_address);

                let result = collect_new_fragments(repository, state_from, state_to, true).await;

                let err = result.expect_err(
                    "Expected collect_new_fragments to propagate a SlowDown hit on a \
                     fragmented payload's child fragment",
                );
                assert!(
                    err.is_slow_down(),
                    "Expected StateError::SlowDown, got: {err:?}"
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_new_fragments_fragmented_walk_yields_child_addresses_when_unarmed() {
        // Positive control for the fragmented-payload fixture itself: with no
        // fault armed at all, `collect_new_fragments` must walk into the
        // `PayloadFragmented` root and report both of its children as new,
        // plus the root address itself. Without this, a regression that
        // stopped the fixture from producing a real `PayloadFragmented` root
        // (or that stopped `collect_new_addresses` from recursing into one at
        // all) would let the neighboring SlowDown-propagation tests pass
        // vacuously -- they only assert on the `Err` path, which a walk that
        // never reaches the fragmented root would also (trivially) satisfy by
        // never hitting the armed fault in the first place.
        with_fragmented_file_fixture(
            |repository,
             state_from,
             state_to,
             _fault_store,
             root_address,
             chunk_one_address,
             chunk_two_address| async move {
                let fragments = collect_new_fragments(repository, state_from, state_to, true)
                    .await
                    .expect("Unarmed fragmented-payload walk must not itself return an error");

                assert!(
                    fragments.contains(&root_address),
                    "Expected the fragmented payload's own root address in the result, got: \
                     {fragments:?}"
                );
                assert!(
                    fragments.contains(&chunk_one_address),
                    "Expected the fragmented payload's first child address in the result \
                     (proves the walk actually recursed into the fragment-reference list), \
                     got: {fragments:?}"
                );
                assert!(
                    fragments.contains(&chunk_two_address),
                    "Expected the fragmented payload's second child address in the result, \
                     got: {fragments:?}"
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_new_fragments_propagates_slow_down_from_own_fragmented_payload_load() {
        // This keeps the Part 2b characterization pin but flips its assertion
        // to the corrected Part 2c behavior. A persistent local SlowDown must
        // reach the existing fragment-walk overload arm before an offline
        // remote fallback can replace its classification.
        with_fragmented_file_fixture(
            |repository,
             state_from,
             state_to,
             fault_store,
             root_address,
             _chunk_one_address,
             _chunk_two_address| async move {
                fault_store.arm_slow_down_get_for(root_address);

                let err = collect_new_fragments(repository, state_from, state_to, true)
                    .await
                    .expect_err(
                        "A SlowDown while loading a fragmented payload's own content must \
                         propagate instead of silently dropping its child addresses",
                    );

                assert!(
                    err.is_slow_down(),
                    "Expected StateError::SlowDown, got: {err:?}"
                );
            },
        )
        .await;
    }

    /// Helper to create a Node with specific flags for testing
    fn node_with_flags(flags: u16) -> Node {
        Node {
            flags,
            ..Default::default()
        }
    }

    use lore_revision::change;
    use lore_revision::change::FileAction;
    use lore_revision::state::compute_change_flags;

    #[test]
    fn returns_none_for_default_node_with_valid_to() {
        let node = Node::default();
        let flags = compute_change_flags(&node, FileAction::Keep, true);
        assert_eq!(flags, change::Flags::None);
    }

    #[test]
    fn sets_modify_flag_for_keep_action_with_invalid_to_node() {
        let node = Node::default();
        let flags = compute_change_flags(&node, FileAction::Keep, false);
        assert!(flags.contains(change::Flags::Modify));
    }

    #[test]
    fn does_not_set_modify_flag_for_add_action_with_invalid_to_node() {
        let node = Node::default();
        let flags = compute_change_flags(&node, FileAction::Add, false);
        assert!(!flags.contains(change::Flags::Modify));
    }

    #[test]
    fn does_not_set_modify_flag_for_delete_action_with_invalid_to_node() {
        let node = Node::default();
        let flags = compute_change_flags(&node, FileAction::Delete, false);
        assert!(!flags.contains(change::Flags::Modify));
    }

    #[test]
    fn sets_staged_flag_when_node_is_staged() {
        let node = node_with_flags(NodeFlags::Staged.bits());
        let flags = compute_change_flags(&node, FileAction::Keep, true);
        assert!(flags.contains(change::Flags::Staged));
    }

    #[test]
    fn sets_merge_flag_when_node_is_staged_merge() {
        let node = node_with_flags(NodeFlags::StagedMerge.bits());
        let flags = compute_change_flags(&node, FileAction::Keep, true);
        assert!(flags.contains(change::Flags::Merge));
    }

    #[test]
    fn sets_conflict_flag_when_node_is_merge_conflict() {
        let node = node_with_flags(NodeFlags::StagedMergeConflict.bits());
        let flags = compute_change_flags(&node, FileAction::Keep, true);
        assert!(flags.contains(change::Flags::Conflict));
    }

    #[test]
    fn sets_conflict_resolved_flag_when_node_is_merge_resolved() {
        let node = node_with_flags(NodeFlags::StagedMergeResolved.bits());
        let flags = compute_change_flags(&node, FileAction::Keep, true);
        assert!(flags.contains(change::Flags::ConflictResolved));
    }

    #[test]
    fn sets_conflict_mine_flag_when_node_is_merge_mine() {
        let node = node_with_flags(NodeFlags::StagedMergeMine.bits());
        let flags = compute_change_flags(&node, FileAction::Keep, true);
        assert!(flags.contains(change::Flags::ConflictMine));
    }

    #[test]
    fn sets_conflict_theirs_flag_when_node_is_merge_theirs() {
        let node = node_with_flags(NodeFlags::StagedMergeTheirs.bits());
        let flags = compute_change_flags(&node, FileAction::Keep, true);
        assert!(flags.contains(change::Flags::ConflictTheirs));
    }

    #[test]
    fn combines_multiple_flags() {
        // Node that is staged and also a merge conflict
        let node = node_with_flags(NodeFlags::StagedMergeConflict.bits());
        let flags = compute_change_flags(&node, FileAction::Keep, false);
        // Should have Modify (from invalid to), Staged, Merge, and Conflict
        assert!(flags.contains(change::Flags::Modify));
        assert!(flags.contains(change::Flags::Staged));
        assert!(flags.contains(change::Flags::Merge));
        assert!(flags.contains(change::Flags::Conflict));
    }
}

mod single_file_compare_result_tests {
    use std::path::Path;
    use std::sync::Arc;

    use lore_base::error::NoRemote;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_revision::change;
    use lore_revision::change::FileAction;
    use lore_revision::change::NodeChange;
    use lore_revision::change::NodeChangeState;
    use lore_revision::filter::Filter;
    use lore_revision::node::INVALID_NODE;
    use lore_revision::node::NodeFlags;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryFormat;
    use lore_revision::state::SingleFileCompareResult;
    use lore_revision::state::State;
    use lore_revision::state::detect_and_coalesce_moves;
    use lore_revision::util::path::RelativePath;
    use lore_storage::local::immutable_store;
    use lore_storage::local::mutable_store;
    use lore_transport::ProtocolError;

    #[test]
    fn debug_format_displays_variant_names() {
        assert_eq!(
            format!("{:?}", SingleFileCompareResult::Unmodified),
            "Unmodified"
        );
        assert_eq!(
            format!("{:?}", SingleFileCompareResult::Modified),
            "Modified"
        );
        assert_eq!(format!("{:?}", SingleFileCompareResult::NewFile), "NewFile");
        assert_eq!(
            format!("{:?}", SingleFileCompareResult::TypeChangedToFile),
            "TypeChangedToFile"
        );
        assert_eq!(
            format!("{:?}", SingleFileCompareResult::TypeChangedToDirectory),
            "TypeChangedToDirectory"
        );
    }

    fn make_change_state(repository: Arc<RepositoryContext>, context: Context) -> NodeChangeState {
        NodeChangeState {
            repository,
            state: Arc::new(State::new()),
            node: INVALID_NODE,
            flags: NodeFlags::NoFlags,
            address: Address {
                hash: Hash::default(),
                context,
            },
        }
    }

    fn make_change(
        repository: Arc<RepositoryContext>,
        action: FileAction,
        path: &str,
        from_context: Context,
        to_context: Context,
    ) -> NodeChange {
        NodeChange {
            action,
            flags: change::Flags::None,
            from: make_change_state(repository.clone(), from_context),
            to: make_change_state(repository, to_context),
            path: RelativePath::new_from_initial_path(path).unwrap_or_default(),
            from_path: None,
        }
    }

    /// Create a Context from a u128 value for testing
    fn context_from_u128(value: u128) -> Context {
        Context::from(value.to_ne_bytes())
    }

    #[tokio::test]
    async fn empty_changes_remains_empty() {
        let mut changes: Vec<NodeChange> = vec![];
        detect_and_coalesce_moves(&mut changes);
        assert!(changes.is_empty());
    }

    /// Create a test repository context
    async fn new_test_context() -> Arc<RepositoryContext> {
        let immutable = immutable_store::LocalImmutableStore::new(
            None,
            immutable_store::ImmutableStoreSettings::default(),
        )
        .await
        .expect("Failed to create store");
        Arc::new(RepositoryContext::new(
            None,
            immutable.clone(),
            Arc::new(
                mutable_store::LocalMutableStore::new(
                    None::<&Path>,
                    lore_storage::MutableStoreSettings::default(),
                    immutable,
                )
                .await
                .expect("Failed to create store"),
            ),
            Context::default().into(),
            lore_revision::instance::InstanceId::default(),
            Err(ProtocolError::from(NoRemote)),
            Arc::new(Filter::default()),
            RepositoryFormat::Lore,
        ))
    }

    #[tokio::test]
    async fn single_add_remains_unchanged() {
        let repo = new_test_context().await;
        let ctx = context_from_u128(1);
        let mut changes = vec![make_change(
            repo,
            FileAction::Add,
            "new_file.txt",
            Context::default(),
            ctx,
        )];

        detect_and_coalesce_moves(&mut changes);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, FileAction::Add);
        assert_eq!(changes[0].path.as_str(), "new_file.txt");
    }

    #[tokio::test]
    async fn single_delete_remains_unchanged() {
        let repo = new_test_context().await;
        let ctx = context_from_u128(1);
        let mut changes = vec![make_change(
            repo,
            FileAction::Delete,
            "deleted_file.txt",
            ctx,
            Context::default(),
        )];

        detect_and_coalesce_moves(&mut changes);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, FileAction::Delete);
        assert_eq!(changes[0].path.as_str(), "deleted_file.txt");
    }

    #[tokio::test]
    async fn matching_add_delete_coalesced_to_move() {
        let repo = new_test_context().await;
        let file_id = context_from_u128(42);

        let mut changes = vec![
            make_change(
                repo.clone(),
                FileAction::Delete,
                "old/path.txt",
                file_id,
                Context::default(),
            ),
            make_change(
                repo,
                FileAction::Add,
                "new/path.txt",
                Context::default(),
                file_id,
            ),
        ];

        detect_and_coalesce_moves(&mut changes);

        // Should have exactly one move change
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, FileAction::Move);
        assert_eq!(changes[0].path.as_str(), "new/path.txt");
        assert_eq!(
            changes[0].from_path.as_ref().map(|p| p.as_str()),
            Some("old/path.txt")
        );
    }

    #[tokio::test]
    async fn multiple_independent_moves_coalesced() {
        let repo = new_test_context().await;
        let file_id_1 = context_from_u128(1);
        let file_id_2 = context_from_u128(2);

        let mut changes = vec![
            make_change(
                repo.clone(),
                FileAction::Delete,
                "old/file1.txt",
                file_id_1,
                Context::default(),
            ),
            make_change(
                repo.clone(),
                FileAction::Delete,
                "old/file2.txt",
                file_id_2,
                Context::default(),
            ),
            make_change(
                repo.clone(),
                FileAction::Add,
                "new/file1.txt",
                Context::default(),
                file_id_1,
            ),
            make_change(
                repo,
                FileAction::Add,
                "new/file2.txt",
                Context::default(),
                file_id_2,
            ),
        ];

        detect_and_coalesce_moves(&mut changes);

        // Should have exactly two move changes
        assert_eq!(changes.len(), 2);

        // Both should be moves
        assert!(changes.iter().all(|c| c.action == FileAction::Move));

        // Both should have from_path set
        assert!(changes.iter().all(|c| c.from_path.is_some()));
    }

    #[tokio::test]
    async fn unmatched_add_and_delete_remain_unchanged() {
        let repo = new_test_context().await;
        let file_id_1 = context_from_u128(1);
        let file_id_2 = context_from_u128(2);

        let mut changes = vec![
            make_change(
                repo.clone(),
                FileAction::Delete,
                "deleted.txt",
                file_id_1,
                Context::default(),
            ),
            make_change(
                repo,
                FileAction::Add,
                "added.txt",
                Context::default(),
                file_id_2,
            ),
        ];

        detect_and_coalesce_moves(&mut changes);

        // Both should remain as they don't share context
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.action == FileAction::Delete));
        assert!(changes.iter().any(|c| c.action == FileAction::Add));
    }

    #[tokio::test]
    async fn zero_context_not_matched() {
        let repo = new_test_context().await;
        let zero_ctx = Context::default();

        let mut changes = vec![
            make_change(
                repo.clone(),
                FileAction::Delete,
                "deleted.txt",
                zero_ctx,
                zero_ctx,
            ),
            make_change(repo, FileAction::Add, "added.txt", zero_ctx, zero_ctx),
        ];

        detect_and_coalesce_moves(&mut changes);

        // Should remain unchanged since zero context is ignored
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.action == FileAction::Delete));
        assert!(changes.iter().any(|c| c.action == FileAction::Add));
    }

    #[tokio::test]
    async fn keep_changes_not_affected() {
        let repo = new_test_context().await;
        let file_id = context_from_u128(1);

        let mut changes = vec![
            make_change(
                repo.clone(),
                FileAction::Keep,
                "modified.txt",
                file_id,
                file_id,
            ),
            make_change(
                repo,
                FileAction::Delete,
                "old.txt",
                file_id,
                Context::default(),
            ),
        ];

        detect_and_coalesce_moves(&mut changes);

        // Keep should remain, delete should remain (no matching add)
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.action == FileAction::Keep));
        assert!(changes.iter().any(|c| c.action == FileAction::Delete));
    }

    #[tokio::test]
    async fn mixed_changes_only_moves_coalesced() {
        let repo = new_test_context().await;
        let move_file_id = context_from_u128(1);
        let keep_file_id = context_from_u128(2);
        let delete_file_id = context_from_u128(3);
        let add_file_id = context_from_u128(4);

        let mut changes = vec![
            make_change(
                repo.clone(),
                FileAction::Delete,
                "moved_from.txt",
                move_file_id,
                Context::default(),
            ),
            make_change(
                repo.clone(),
                FileAction::Keep,
                "kept.txt",
                keep_file_id,
                keep_file_id,
            ),
            make_change(
                repo.clone(),
                FileAction::Delete,
                "truly_deleted.txt",
                delete_file_id,
                Context::default(),
            ),
            make_change(
                repo.clone(),
                FileAction::Add,
                "moved_to.txt",
                Context::default(),
                move_file_id,
            ),
            make_change(
                repo,
                FileAction::Add,
                "truly_added.txt",
                Context::default(),
                add_file_id,
            ),
        ];

        detect_and_coalesce_moves(&mut changes);

        // Should have 4 changes: 1 move, 1 keep, 1 delete, 1 add
        assert_eq!(changes.len(), 4);
        assert_eq!(
            changes
                .iter()
                .filter(|c| c.action == FileAction::Move)
                .count(),
            1
        );
        assert_eq!(
            changes
                .iter()
                .filter(|c| c.action == FileAction::Keep)
                .count(),
            1
        );
        assert_eq!(
            changes
                .iter()
                .filter(|c| c.action == FileAction::Delete)
                .count(),
            1
        );
        assert_eq!(
            changes
                .iter()
                .filter(|c| c.action == FileAction::Add)
                .count(),
            1
        );

        // The move should have correct from_path
        let move_change = changes
            .iter()
            .find(|c| c.action == FileAction::Move)
            .unwrap();
        assert_eq!(move_change.path.as_str(), "moved_to.txt");
        assert_eq!(
            move_change.from_path.as_ref().map(|p| p.as_str()),
            Some("moved_from.txt")
        );
    }

    #[tokio::test]
    async fn from_state_copied_from_delete_to_move() {
        let repo = new_test_context().await;
        let file_id = context_from_u128(42);

        let mut delete_change = make_change(
            repo.clone(),
            FileAction::Delete,
            "old/path.txt",
            file_id,
            Context::default(),
        );
        // Set a specific from address hash to verify it's copied
        delete_change.from.address.hash = Hash::from_u64(12345);

        let mut changes = vec![
            delete_change,
            make_change(
                repo,
                FileAction::Add,
                "new/path.txt",
                Context::default(),
                file_id,
            ),
        ];

        detect_and_coalesce_moves(&mut changes);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, FileAction::Move);
        // The from state should have been copied from the delete
        // Verify that the from address was copied (using the hash we set)
        assert_eq!(changes[0].from.address.hash, Hash::from_u64(12345));
        // Also verify the file_id (context) is preserved in the from state
        assert_eq!(changes[0].from.address.context, file_id);
    }
}

/// Tests for `is_file_modified` chunking compatibility: files stored with
/// old-style fragmentation (multiple 64 KiB chunks) must be recognized as
/// unmodified when the current chunking threshold (256 KiB) would hash them
/// as a single buffer.
mod is_file_modified_chunking_compat {
    #![allow(clippy::disallowed_methods)] // Test fixture writes; not subject to repository write-token discipline.

    use std::sync::Arc;

    use bytes::Bytes;
    use lore_base::error::NoRemote;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_base::types::Fragment;
    use lore_base::types::FragmentFlags;
    use lore_base::types::FragmentReference;
    use lore_base::types::Hash;
    use lore_revision::immutable;
    use lore_revision::node::Node;
    use lore_revision::node::NodeFlags;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryFormat;
    use lore_revision::state::is_file_modified;
    use lore_revision::util::path::RelativePath;
    use lore_transport::ProtocolError;
    use rand::Rng;
    use zerocopy::IntoBytes;

    include!("helper.rs");

    /// Store raw content chunks and a fragment list that references them,
    /// returning the root address whose hash is the hash of the fragment list
    /// payload. This simulates content that was written under the old 64 KiB
    /// chunking threshold.
    async fn store_as_legacy_chunks(
        repository: &Arc<RepositoryContext>,
        context: Context,
        content: &[u8],
        chunk_size: usize,
    ) -> Address {
        let chunks: Vec<&[u8]> = content.chunks(chunk_size).collect();

        // Store each chunk as a raw fragment
        let mut refs = Vec::with_capacity(chunks.len());
        let mut offset: u64 = 0;
        for chunk in &chunks {
            let chunk_bytes = Bytes::copy_from_slice(chunk);
            let hash = Hash::hash_buffer(chunk);
            let address = Address { hash, context };
            let fragment = Fragment {
                flags: FragmentFlags::PayloadStoredLocal.bits(),
                size_payload: chunk.len() as u32,
                size_content: chunk.len() as u64,
            };
            immutable::store_raw(
                repository.clone(),
                address,
                fragment,
                chunk_bytes,
                true,
                false,
            )
            .await
            .expect("Failed to store chunk fragment");

            refs.push(FragmentReference {
                hash,
                offset_content: offset,
            });
            offset += chunk.len() as u64;
        }

        // Serialize the fragment reference list to bytes
        let list_bytes: Vec<u8> = refs.as_slice().as_bytes().to_vec();
        let list_bytes = Bytes::from(list_bytes);
        let list_hash = Hash::hash_buffer(list_bytes.as_ref());

        // Store the fragment list with PayloadFragmented flag
        let list_address = Address {
            hash: list_hash,
            context,
        };
        let list_fragment = Fragment {
            flags: FragmentFlags::PayloadStoredLocal.bits()
                | FragmentFlags::PayloadFragmented.bits(),
            size_payload: list_bytes.len() as u32,
            size_content: content.len() as u64,
        };
        immutable::store_raw(
            repository.clone(),
            list_address,
            list_fragment,
            list_bytes,
            true,
            false,
        )
        .await
        .expect("Failed to store fragment list");

        list_address
    }

    /// 128 KiB file stored as two 64 KiB chunks (old chunking strategy).
    /// The file on disk is unmodified — `is_file_modified` must detect this
    /// via content comparison despite the hash mismatch.
    #[tokio::test]
    async fn unmodified_128k_file_with_legacy_two_chunk_fragmentation() {
        let tempdir = generate_tempdir();
        let dir = tempdir.path().to_path_buf();

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        LORE_CONTEXT
            .scope(execution.clone(), async move {
                let mut rng = rand::rng();
                let context: Context = rand::random();
                let repository_id = rand::random();

                let repository = Arc::new(RepositoryContext::new(
                    Some(dir.as_path().to_path_buf()),
                    immutable_store,
                    mutable_store,
                    repository_id,
                    lore_revision::instance::InstanceId::default(),
                    Err(ProtocolError::from(NoRemote)),
                    Arc::default(),
                    RepositoryFormat::Lore,
                ));

                // Generate 128 KiB of random content
                let content_size = 128 * 1024;
                let content: Vec<u8> = (0..content_size)
                    .map(|_| rng.random_range(0..=255u8))
                    .collect();

                // Store as two 64 KiB chunks (simulating old chunking strategy)
                let root_address =
                    store_as_legacy_chunks(&repository, context, &content, 64 * 1024).await;

                // Write the identical content to a file on disk
                let file_path = dir.join("test_file_128k.bin");
                std::fs::write(&file_path, &content).expect("Failed to write test file");

                let metadata = std::fs::metadata(&file_path).expect("Failed to get metadata");
                let relative_path =
                    RelativePath::new_from_initial_path("test_file_128k.bin").unwrap();

                // Build a Node referencing the legacy chunked address
                let node = Node {
                    flags: NodeFlags::File.bits(),
                    size: content_size as u64,
                    address: root_address,
                    ..Default::default()
                };

                // is_file_modified should detect content equality despite hash mismatch
                let (mtime, size) = lore_revision::util::fs::file_mtime_and_size(&metadata);
                let (modified, new_hash) = is_file_modified(
                    repository.clone(),
                    &node,
                    mtime,
                    size,
                    &relative_path,
                    true, // force hash check
                )
                .await
                .expect("is_file_modified failed");

                assert!(
                    !modified,
                    "128 KiB file with legacy two-chunk fragmentation should NOT be detected as modified"
                );

                // The returned hash (computed with current chunking) must differ
                // from the stored legacy fragment-list hash — this confirms the
                // content comparison fallback was actually exercised.
                assert_ne!(
                    new_hash, root_address.hash,
                    "Returned hash should differ from legacy chunked hash"
                );
                assert!(
                    !new_hash.is_zero(),
                    "Returned hash should be non-zero"
                );

                // The new hash should be a direct hash of the full content
                let expected_hash = Hash::hash_buffer(&content);
                assert_eq!(
                    new_hash, expected_hash,
                    "Returned hash should be the new CDC-based single-buffer hash"
                );
            })
            .await;
    }

    /// 640 KiB file stored as ten 64 KiB chunks. Verifies that rehashing
    /// reuses the previous chunk fragmentation — each chunk is validated
    /// individually and the stored root hash is returned unchanged.
    #[tokio::test]
    async fn unmodified_640k_file_reuses_previous_chunk_fragmentation() {
        let tempdir = generate_tempdir();
        let dir = tempdir.path().to_path_buf();

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        LORE_CONTEXT
            .scope(execution.clone(), async move {
                let mut rng = rand::rng();
                let context: Context = rand::random();
                let repository_id = rand::random();

                let repository = Arc::new(RepositoryContext::new(
                    Some(dir.as_path().to_path_buf()),
                    immutable_store,
                    mutable_store,
                    repository_id,
                    lore_revision::instance::InstanceId::default(),
                    Err(ProtocolError::from(NoRemote)),
                    Arc::default(),
                    RepositoryFormat::Lore,
                ));

                // Generate 640 KiB of random content
                let content_size = 640 * 1024;
                let content: Vec<u8> = (0..content_size)
                    .map(|_| rng.random_range(0..=255u8))
                    .collect();

                // Store as ten 64 KiB chunks (simulating old chunking strategy)
                let root_address =
                    store_as_legacy_chunks(&repository, context, &content, 64 * 1024).await;

                // Write the identical content to a file on disk
                let file_path = dir.join("test_file_640k.bin");
                std::fs::write(&file_path, &content).expect("Failed to write test file");

                let metadata = std::fs::metadata(&file_path).expect("Failed to get metadata");
                let relative_path =
                    RelativePath::new_from_initial_path("test_file_640k.bin").unwrap();

                // Build a Node referencing the legacy chunked address
                let node = Node {
                    flags: NodeFlags::File.bits(),
                    size: content_size as u64,
                    address: root_address,
                    ..Default::default()
                };

                // is_file_modified should detect content equality despite hash mismatch
                let (mtime, size) = lore_revision::util::fs::file_mtime_and_size(&metadata);
                let (modified, new_hash) = is_file_modified(
                    repository.clone(),
                    &node,
                    mtime,
                    size,
                    &relative_path,
                    true, // force hash check
                )
                .await
                .expect("is_file_modified failed");

                assert!(
                    !modified,
                    "640 KiB file with legacy ten-chunk fragmentation should NOT be detected as modified"
                );

                // For files > 256 KiB, hash_file validates each chunk against
                // the previous fragment list and returns the stored root hash
                // when all chunks match. The content comparison fallback is NOT
                // needed here — the chunk-level validation succeeds directly.
                assert_eq!(
                    new_hash, root_address.hash,
                    "Returned hash should equal the stored hash (chunk validation path)"
                );
            })
            .await;
    }
}
