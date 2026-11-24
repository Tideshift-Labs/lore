// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod net_common {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use bytes::Bytes;
    use lore::storage::close::LoreStorageCloseArgs;
    use lore::storage::handle::LoreStore;
    use lore::storage::open::LoreStorageOpenArgs;
    use lore::storage::open::LoreStorageRemoteConfig;
    use lore::storage::put::LoreStoragePutArgs;
    use lore::storage::put::LoreStoragePutItem;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_base::types::Fragment;
    use lore_base::types::HealResult;
    use lore_base::types::Partition;
    use lore_revision::environment::EnvironmentConfig;
    use lore_revision::event::LoreBytes;
    use lore_revision::event::LoreEvent;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreEventCallback;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
    use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::grpc::server::GrpcTimeouts;
    use lore_server::hooks::HookDispatcher;
    use lore_server::settings::BaselineAccess;
    use lore_storage::CorrelationHold;
    use lore_storage::FlushOptions;
    use lore_storage::ImmutableStore;
    use lore_storage::StoreError;
    use lore_storage::StoreGetData;
    use lore_storage::StoreMatch;
    use lore_storage::StoreMatchResult;
    use lore_storage::StoreObliterateStats;
    use lore_storage::gc_event::GcEventSinkRef;
    use lore_storage::immutable_store::CopyBehavior;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_storage::local::store_lock::StoreGuard;
    use lore_storage::local::store_lock::StoreLock;

    /// Maximum candidates tried, OS-assigned and random together.
    pub(crate) const PORT_PAIR_ATTEMPTS: usize = 100;

    /// The IANA dynamic range that random fallback candidates are drawn from.
    const DYNAMIC_PORTS: std::ops::RangeInclusive<u16> = 49152..=65535;

    /// Where the leading TCP socket of one candidate binds.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Candidate {
        /// Port 0: the OS picks.
        Assigned,
        /// A random port from `DYNAMIC_PORTS`.
        At(u16),
    }

    /// A TCP listener and a UDP socket on the same port, both held exclusively.
    ///
    /// A `lore://` server serves gRPC on TCP and QUIC on UDP at one number, and no bind can reserve
    /// a number for the other protocol. So the port is not chosen and then bound twice — it is
    /// bound on TCP, matched on UDP, and handed to the servers already bound. Nothing can take
    /// either between choosing and serving, because there is no such gap.
    ///
    /// Neither socket sets a reuse option. Failed candidates stay reserved until this search ends,
    /// preventing immediate reuse. The first candidate is OS-assigned. Every later one is random:
    /// Windows excludes port ranges per protocol in blocks of 100 (Hyper-V, WSL, `WinNAT`), and
    /// the OS hands out ports sequentially, so asking it again keeps landing in the same block.
    /// A random loopback bind can succeed over another process's wildcard bind of the same port;
    /// the matching bind always had that exposure, and the OS-assigned first candidate does not.
    pub(crate) fn bind_matched_pair() -> (std::net::TcpListener, std::net::UdpSocket) {
        reserve_matched_pair(
            PORT_PAIR_ATTEMPTS,
            random_port,
            |candidate| match candidate {
                Candidate::Assigned => std::net::TcpListener::bind("127.0.0.1:0"),
                Candidate::At(port) => {
                    std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|error| {
                        std::io::Error::new(error.kind(), format!("TCP port {port}: {error}"))
                    })
                }
            },
            |tcp| {
                let port = tcp.local_addr()?.port();
                std::net::UdpSocket::bind(("127.0.0.1", port)).map_err(|error| {
                    std::io::Error::new(error.kind(), format!("UDP port {port}: {error}"))
                })
            },
        )
        .unwrap_or_else(|error| panic!("cannot reserve matched TCP/UDP sockets: {error}"))
    }

    fn random_port() -> u16 {
        rand::random_range(DYNAMIC_PORTS)
    }

    /// Bind up to `attempts` candidates until one matches. An OS-assigned bind failure is fatal,
    /// because the OS has no port to give. A random bind failure only costs that candidate.
    fn reserve_matched_pair<T, U>(
        attempts: usize,
        mut next_random: impl FnMut() -> u16,
        mut bind_leading: impl FnMut(Candidate) -> std::io::Result<T>,
        mut bind_matching: impl FnMut(&T) -> std::io::Result<U>,
    ) -> std::io::Result<(T, U)> {
        let mut rejected = Vec::new();
        let mut last_error = None;
        for attempt in 0..attempts {
            let candidate = if attempt == 0 {
                Candidate::Assigned
            } else {
                Candidate::At(next_random())
            };
            let leading = match bind_leading(candidate) {
                Ok(leading) => leading,
                Err(error) if candidate == Candidate::Assigned => return Err(error),
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            match bind_matching(&leading) {
                Ok(matching) => return Ok((leading, matching)),
                Err(error) => {
                    last_error = Some(error);
                    rejected.push(leading);
                }
            }
        }
        Err(std::io::Error::other(format!(
            "no matching socket after {attempts} candidates ({} reserved); last failure: {:?}",
            rejected.len(),
            last_error
        )))
    }

    /// Waits until a connect's first back-off, its jitter included, has passed.
    pub(crate) async fn wait_out_connect_back_off() {
        tokio::time::sleep(std::time::Duration::from_millis(
            lore_transport::connection::RECONNECT_START_DELAY + lore_base::retry::JITTER_CLAMP_MS,
        ))
        .await;
    }

    /// The connection to the remote at `url`, as the process-wide connection cache holds it.
    /// `None` once no live connection to it is cached.
    pub(crate) fn cached_connection(
        url: &str,
    ) -> Option<std::sync::Arc<lore_transport::Connection>> {
        let (url, _protocol) = lore_transport::parse(url).expect("server url parses");
        lore_transport::find_connection(
            url.as_str(),
            "",
            false,
            lore_revision::interface::LoreGlobalArgs::default().auth_mode,
        )
    }

    /// Binds a port on the loopback interface and serves gRPC on it as [`spawn_grpc_server`]
    /// does. Returns the server's `grpc://` URL, and what stops it.
    pub(crate) fn start_grpc_server(
        backend_immutable: Arc<dyn lore_storage::ImmutableStore>,
        backend_mutable: Arc<dyn lore_storage::MutableStore>,
    ) -> (String, TestServerStop) {
        start_grpc_server_with(
            backend_immutable,
            backend_mutable,
            Arc::new(AllowAllRepositoryAuthorizer),
        )
    }

    /// [`start_grpc_server`] with `authorizer` deciding each request's access.
    pub(crate) fn start_grpc_server_with(
        backend_immutable: Arc<dyn lore_storage::ImmutableStore>,
        backend_mutable: Arc<dyn lore_storage::MutableStore>,
        authorizer: Arc<dyn RepositoryAuthorizer>,
    ) -> (String, TestServerStop) {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("binds a port to serve on");
        let addr = listener.local_addr().expect("the listener has an address");
        let stop = spawn_grpc_server_with(listener, backend_immutable, backend_mutable, authorizer);
        (format!("grpc://{addr}"), stop)
    }

    /// Serves gRPC on `listener` until the returned [`TestServerStop`] stops it or is dropped.
    pub(crate) fn spawn_grpc_server(
        listener: std::net::TcpListener,
        backend_immutable: Arc<dyn lore_storage::ImmutableStore>,
        backend_mutable: Arc<dyn lore_storage::MutableStore>,
    ) -> TestServerStop {
        spawn_grpc_server_with(
            listener,
            backend_immutable,
            backend_mutable,
            Arc::new(AllowAllRepositoryAuthorizer),
        )
    }

    /// [`spawn_grpc_server`] with `authorizer` deciding each request's access.
    pub(crate) fn spawn_grpc_server_with(
        listener: std::net::TcpListener,
        backend_immutable: Arc<dyn lore_storage::ImmutableStore>,
        backend_mutable: Arc<dyn lore_storage::MutableStore>,
        authorizer: Arc<dyn RepositoryAuthorizer>,
    ) -> TestServerStop {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
        let serve_ended = Arc::new(AtomicBool::new(false));
        let ended = serve_ended.clone();

        let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
            Arc::new(lore_server::notification::local::NotificationSender::default());
        let hook_dispatcher = Arc::new(HookDispatcher::empty());

        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move {
            let repository_catalog = Arc::new(BaselineRepositoryCatalog::new(
                BaselineAccess::Reachable,
                backend_immutable.clone(),
                backend_mutable.clone(),
            ));
            let outcome = GrpcServerBuilder::new()
                .with_environment(EnvironmentConfig::default())
                .with_feature(FeatureSettings::default())
                .with_immutable_store(backend_immutable.clone(), backend_immutable, None)
                .with_mutable_store(backend_mutable)
                .with_lock_store(None)
                // CR-029 inserted this step; `None` is the non-Postgres cell path these
                // harnesses run, which is the same unsynchronised behaviour as before.
                .with_domain_context(None)
                .with_notification(notification_sender, None)
                .with_hook_dispatcher(hook_dispatcher)
                .with_tls_config(None, None, None)
                .unwrap()
                .with_admin_endpoints(HashMap::new(), vec![])
                .with_http2_config(
                    None,
                    None,
                    GrpcTimeouts {
                        request_handler: Duration::from_secs(30),
                        authorization: Duration::from_secs(30),
                    },
                    Default::default(),
                    Default::default(),
                    None,
                )
                .with_token_verification(
                    lore_server::auth::jwt::TokenVerification::Ignore,
                    false,
                    authorizer,
                    repository_catalog,
                )
                .unwrap()
                .serve_with_listener(listener, async {
                    shutdown_rx.await.ok();
                })
                .await;
            ended.store(true, Ordering::Release);
            let _ = stopped_tx.send(outcome.map_err(|error| format!("{error:#}")));
        });

        TestServerStop {
            quic: None,
            shutdown: Some(shutdown_tx),
            stopped: Some(stopped_rx),
            serve_ended,
        }
    }

    /// Bound on the wait for a test gRPC server's stop report.
    const SHUTDOWN_WAIT: Duration = Duration::from_secs(10);

    /// What stops a test server: the QUIC server of a `lore://` server, the sender whose drop
    /// stops the gRPC server [`spawn_grpc_server`] started, and the receiver of its stop report.
    /// Dropped, it signals the stop and waits for none of it.
    pub(crate) struct TestServerStop {
        quic: Option<lore_server::quic::quinn::QuinnServer>,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        stopped: Option<tokio::sync::oneshot::Receiver<Result<(), String>>>,
        /// Set by the gRPC serve task once it has returned, and with it dropped its listener,
        /// before it reports how it stopped.
        serve_ended: Arc<AtomicBool>,
    }

    impl TestServerStop {
        /// Adds `quic`, the QUIC server of a `lore://` server, to what [`Self::stop`] stops.
        pub(crate) fn with_quic(mut self, quic: lore_server::quic::quinn::QuinnServer) -> Self {
            self.quic = Some(quic);
            self
        }

        /// Whether the gRPC serve task has returned, and with it dropped its listener, so the
        /// server accepts no connection.
        pub(crate) fn serve_ended(&self) -> bool {
            self.serve_ended.load(Ordering::Acquire)
        }

        /// Closes the QUIC server's endpoints and waits until they are idle, then stops the
        /// gRPC server and waits for its report of a clean stop, sent once the serve task holding
        /// the TCP listener has returned. Panics unless the report comes within
        /// [`SHUTDOWN_WAIT`]. A part already stopped is skipped.
        pub(crate) async fn stop(&mut self) {
            if let Some(quic) = self.quic.take() {
                quic.close().await;
            }
            drop(self.shutdown.take());
            if let Some(stopped) = self.stopped.take() {
                tokio::time::timeout(SHUTDOWN_WAIT, stopped)
                    .await
                    .expect("the gRPC server stops")
                    .expect("the gRPC server reports how it stopped")
                    .expect("the gRPC server stops cleanly");
            }
        }
    }

    /// Whether a test server's immutable store serves a payload under a partition it doesn't hold
    /// the payload in.
    pub(crate) enum Partitions {
        /// Serves a payload only under a partition it holds it in, as Lore Server's store does.
        Isolated,
        /// Serves a payload it holds under any partition, as a client's store does.
        Shared,
    }

    /// A fresh in-memory store pair for a test server to serve. The immutable store treats every
    /// fragment it holds as durably stored and protects none from eviction, as Lore Server's does,
    /// and isolates partitions as `partitions` says.
    pub(crate) async fn make_backends(
        partitions: Partitions,
    ) -> (
        Arc<dyn lore_storage::ImmutableStore>,
        Arc<dyn lore_storage::MutableStore>,
    ) {
        let backend_immutable = lore_storage::local::immutable_store::create(
            None::<&str>,
            ImmutableStoreCreateOptions::none(),
            false,
            ImmutableStoreSettings {
                protect_local_fragment: false,
                implicit_durable_stored: true,
                isolate_partitions: matches!(partitions, Partitions::Isolated),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let backend_mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            backend_immutable.clone(),
        )
        .await
        .unwrap();

        (backend_immutable, backend_mutable)
    }

    /// Opens an in-memory storage handle, bound to the remote at `remote_url` when one is given.
    pub(crate) async fn open_handle(remote_url: Option<&str>) -> LoreStore {
        open_handle_with_globals(LoreGlobalArgs::default(), remote_url).await
    }

    /// Opens a storage handle as [`open_handle`] does, with `globals` for the open call. The
    /// handle keeps the flags `globals` sets.
    pub(crate) async fn open_handle_with_globals(
        globals: LoreGlobalArgs,
        remote_url: Option<&str>,
    ) -> LoreStore {
        open_handle_with_args(
            globals,
            LoreStorageOpenArgs {
                in_memory: 1,
                remote_config: LoreStorageRemoteConfig {
                    remote_url: LoreString::from(remote_url.unwrap_or_default()),
                },
                has_remote_config: u8::from(remote_url.is_some()),
                ..Default::default()
            },
        )
        .await
    }

    /// Opens a storage handle with `args`, and `globals` for the open call. Panics unless the open
    /// succeeds and reports its handle.
    pub(crate) async fn open_handle_with_args(
        globals: LoreGlobalArgs,
        args: LoreStorageOpenArgs,
    ) -> LoreStore {
        let opened: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let sink = opened.clone();
        let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
            if let LoreEvent::StorageOpened(data) = event {
                *sink.lock().unwrap() = Some(data.handle_id);
            }
        }));
        let status = lore::storage::open::open(globals, args, callback).await;
        assert_eq!(status, 0, "opening the storage handle must succeed");
        let handle_id = opened.lock().unwrap().expect("STORAGE_OPENED must fire");
        LoreStore { handle_id }
    }

    /// Closes the storage handle `handle`. Panics unless the close succeeds.
    pub(crate) async fn close_handle(handle: LoreStore) {
        let status = lore::storage::close::close(
            LoreGlobalArgs::default(),
            LoreStorageCloseArgs {
                handle,
                ..Default::default()
            },
            None,
        )
        .await;
        assert_eq!(status, 0, "close must succeed");
    }

    /// Stores `content` under `context` in `partition` through the storage handle `handle`, as one
    /// put item with the given `remote_write` and `fixed_size_chunk`. Returns the content's
    /// address. Panics unless the put succeeds.
    pub(crate) async fn put_content(
        handle: LoreStore,
        partition: Partition,
        context: Context,
        content: &[u8],
        remote_write: u8,
        fixed_size_chunk: u64,
    ) -> Address {
        let completed: Arc<Mutex<Vec<(Address, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = completed.clone();
        let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
            if let LoreEvent::StoragePutItemComplete(data) = event {
                sink.lock()
                    .unwrap()
                    .push((data.address, data.error.error_code));
            }
        }));
        let status = lore::storage::put::put(
            LoreGlobalArgs::default(),
            LoreStoragePutArgs {
                handle,
                items: LoreArray::from_vec(vec![LoreStoragePutItem {
                    id: 1,
                    partition,
                    context,
                    data: LoreBytes {
                        ptr: content.as_ptr().cast(),
                        len: content.len(),
                    },
                    remote_write,
                    local_cache: 0,
                    remote_query: 0,
                    fixed_size_chunk,
                }]),
            },
            callback,
        )
        .await;
        assert_eq!(status, 0, "put must succeed");
        let completed = completed.lock().unwrap();
        assert_eq!(completed.len(), 1, "the put completes its one item once");
        assert_eq!(completed[0].1, 0, "the item must succeed");
        completed[0].0
    }

    /// The counts of the puts with and without a payload, and of the copies, that reached a
    /// [`CountingStore`].
    #[derive(Debug, Default, PartialEq, Eq)]
    pub(crate) struct Traffic {
        pub payload_puts: usize,
        pub empty_puts: usize,
        pub copies: usize,
    }

    /// An immutable store that forwards every method but `get_into` to the store it wraps and
    /// counts what reaches it: the gets, the metadata reads, the puts with and without a payload,
    /// and the copies, with each copy's source.
    /// One built with [`refusing_copy`](Self::refusing_copy) refuses every copy, as a peer that
    /// won't answer one does. Its `get_into` is the trait's default, which reads through `get`, so
    /// every payload read counts as a get.
    pub(crate) struct CountingStore {
        inner: Arc<dyn ImmutableStore>,
        gets: Arc<AtomicUsize>,
        metadata_reads: AtomicUsize,
        payload_puts: AtomicUsize,
        empty_puts: AtomicUsize,
        copies: AtomicUsize,
        copy_sources: Mutex<Vec<(Partition, Address)>>,
        refuse_copy: bool,
        /// FORK-LOCAL (Tideshift): a copy that applies answers `OutcomeUnknown`, as a lost
        /// answer does.
        pub(crate) lose_copy_response: AtomicBool,
        /// FORK-LOCAL (Tideshift): each put waits here, so a test can hold puts until several
        /// arrive.
        pub(crate) put_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
        /// FORK-LOCAL (Tideshift): a put that applies answers `OutcomeUnknown`, as a lost
        /// answer does.
        pub(crate) lose_put_response: AtomicBool,
    }

    impl CountingStore {
        fn wrapping(inner: Arc<dyn ImmutableStore>, refuse_copy: bool) -> Arc<Self> {
            Arc::new(Self {
                inner,
                gets: Arc::default(),
                metadata_reads: AtomicUsize::new(0),
                payload_puts: AtomicUsize::new(0),
                empty_puts: AtomicUsize::new(0),
                copies: AtomicUsize::new(0),
                copy_sources: Mutex::new(Vec::new()),
                refuse_copy,
                lose_copy_response: AtomicBool::new(false),
                put_barrier: Mutex::new(None),
                lose_put_response: AtomicBool::new(false),
            })
        }

        /// A counting store over `inner`.
        pub(crate) fn new(inner: Arc<dyn ImmutableStore>) -> Arc<Self> {
            Self::wrapping(inner, false)
        }

        /// A counting store over `inner` that refuses every copy with `AddressNotFound`.
        pub(crate) fn refusing_copy(inner: Arc<dyn ImmutableStore>) -> Arc<Self> {
            Self::wrapping(inner, true)
        }

        /// The counter of the gets that reached the store, shared with the caller.
        pub(crate) fn gets(&self) -> Arc<AtomicUsize> {
            self.gets.clone()
        }

        /// The metadata reads that reached the store since it was built or last reset.
        pub(crate) fn metadata_reads(&self) -> usize {
            self.metadata_reads.load(Ordering::SeqCst)
        }

        /// The puts and copies counted since the store was built or last reset.
        pub(crate) fn traffic(&self) -> Traffic {
            Traffic {
                payload_puts: self.payload_puts.load(Ordering::SeqCst),
                empty_puts: self.empty_puts.load(Ordering::SeqCst),
                copies: self.copies.load(Ordering::SeqCst),
            }
        }

        /// Zeroes the metadata read, put and copy counts and clears the recorded copy sources. The
        /// get count is kept.
        pub(crate) fn reset(&self) {
            self.metadata_reads.store(0, Ordering::SeqCst);
            self.payload_puts.store(0, Ordering::SeqCst);
            self.empty_puts.store(0, Ordering::SeqCst);
            self.copies.store(0, Ordering::SeqCst);
            self.copy_sources.lock().unwrap().clear();
        }

        /// The source of each copy that reached the store since it was built or last reset, in
        /// order.
        pub(crate) fn copy_sources(&self) -> Vec<(Partition, Address)> {
            self.copy_sources.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl ImmutableStore for CountingStore {
        async fn hold_for_command(self: Arc<Self>) -> Result<Option<StoreGuard>, StoreError> {
            self.inner.clone().hold_for_command().await
        }

        fn try_join_claim(&self) -> Option<StoreGuard> {
            self.inner.try_join_claim()
        }

        fn store_lock(&self) -> Option<Arc<StoreLock>> {
            self.inner.store_lock()
        }

        fn hold_correlation(&self, correlation_id: &str) -> Option<CorrelationHold> {
            self.inner.hold_correlation(correlation_id)
        }

        async fn hold_for_task(self: Arc<Self>) -> Result<Option<StoreGuard>, StoreError> {
            self.inner.clone().hold_for_task().await
        }

        fn is_local(&self) -> bool {
            self.inner.is_local()
        }

        fn isolates_partitions(&self) -> bool {
            self.inner.isolates_partitions()
        }

        fn read_scope(&self) -> StoreMatch {
            self.inner.read_scope()
        }

        fn query_scope(&self) -> StoreMatch {
            self.inner.query_scope()
        }

        async fn get(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<StoreGetData, StoreError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.clone().get(partition, address).await
        }

        async fn is_available(self: Arc<Self>, timeout: Duration) -> bool {
            self.inner.clone().is_available(timeout).await
        }

        async fn query(
            self: Arc<Self>,
            partition: Partition,
            addresses: &[Address],
            results: &mut [StoreMatchResult],
        ) -> Result<(), StoreError> {
            self.inner
                .clone()
                .query(partition, addresses, results)
                .await
        }

        async fn get_metadata(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<StoreGetData, StoreError> {
            self.metadata_reads.fetch_add(1, Ordering::SeqCst);
            self.inner.clone().get_metadata(partition, address).await
        }

        async fn put(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            fragment: Fragment,
            payload: Option<Bytes>,
            force: bool,
        ) -> Result<(), StoreError> {
            if payload.is_some() {
                self.payload_puts.fetch_add(1, Ordering::SeqCst);
            } else {
                self.empty_puts.fetch_add(1, Ordering::SeqCst);
            }
            let barrier = self.put_barrier.lock().unwrap().clone();
            if let Some(barrier) = barrier {
                barrier.wait().await;
            }
            self.inner
                .clone()
                .put(partition, address, fragment, payload, force)
                .await?;
            if self.lose_put_response.load(Ordering::SeqCst) {
                return Err(StoreError::from(lore_base::error::OutcomeUnknown {
                    operation: "StorageService.Put".into(),
                    attempt_id: uuid::Uuid::now_v7().to_string(),
                }));
            }
            Ok(())
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
            sink: Option<GcEventSinkRef>,
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
            sink: Option<GcEventSinkRef>,
        ) -> Result<Option<usize>, StoreError> {
            self.inner
                .clone()
                .compact(max_size, at, sync_data, sink)
                .await
        }

        async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
            self.inner.clone().compact_resume_at().await
        }

        async fn load_index(self: Arc<Self>) -> Result<(), StoreError> {
            self.inner.clone().load_index().await
        }

        async fn stop_gc(self: Arc<Self>, terminate: bool) {
            self.inner.clone().stop_gc(terminate).await;
        }

        fn max_query_batch(&self) -> Option<usize> {
            self.inner.max_query_batch()
        }

        async fn flush(self: Arc<Self>, options: FlushOptions) -> Result<(), StoreError> {
            self.inner.clone().flush(options).await
        }

        async fn fragment_count(self: Arc<Self>) -> Option<usize> {
            self.inner.clone().fragment_count().await
        }

        async fn verify(self: Arc<Self>, heal: bool) -> Result<(), StoreError> {
            self.inner.clone().verify(heal).await
        }

        async fn heal(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<HealResult, StoreError> {
            self.inner.clone().heal(partition, address).await
        }

        async fn settle(self: Arc<Self>, partition: Partition, address: Address) {
            self.inner.clone().settle(partition, address).await;
        }

        async fn copy(
            self: Arc<Self>,
            source_partition: Partition,
            source_address: Address,
            destination_partition: Partition,
            destination_context: Context,
            behavior: CopyBehavior,
        ) -> Result<(), StoreError> {
            self.copies.fetch_add(1, Ordering::SeqCst);
            self.copy_sources
                .lock()
                .unwrap()
                .push((source_partition, source_address));
            if self.refuse_copy {
                return Err(StoreError::from(lore_base::error::AddressNotFound::from(
                    source_address,
                )));
            }
            let result = self
                .inner
                .clone()
                .copy(
                    source_partition,
                    source_address,
                    destination_partition,
                    destination_context,
                    behavior,
                )
                .await;
            if self.lose_copy_response.load(Ordering::SeqCst) {
                result?;
                return Err(StoreError::from(lore_base::error::OutcomeUnknown {
                    operation: "StorageService.Copy".into(),
                    attempt_id: uuid::Uuid::now_v7().to_string(),
                }));
            }
            result
        }
    }

    #[cfg(test)]
    mod tests {
        use std::cell::RefCell;
        use std::collections::BTreeSet;
        use std::io;
        use std::ops::RangeInclusive;
        use std::rc::Rc;

        use super::Candidate;
        use super::DYNAMIC_PORTS;
        use super::PORT_PAIR_ATTEMPTS;
        use super::random_port;
        use super::reserve_matched_pair;

        #[derive(Debug)]
        struct Reservation(u16, Rc<RefCell<BTreeSet<u16>>>);

        impl Drop for Reservation {
            fn drop(&mut self) {
                assert!(self.1.borrow_mut().remove(&self.0));
            }
        }

        /// A model of the excluded blocks on the failing rig: TCP and UDP blocks together spanned
        /// 55333-57125. Here one protocol holds the whole span.
        const EXCLUDED: RangeInclusive<u16> = 55333..=57125;

        /// Model the OS: port 0 hands out the next number of a sequential allocator that starts
        /// inside the excluded block, a named port binds unless it is held or excluded.
        struct Model {
            held: Rc<RefCell<BTreeSet<u16>>>,
            next_assigned: u16,
            leading_excluded: bool,
        }

        impl Model {
            fn new(leading_excluded: bool) -> Self {
                Model {
                    held: Rc::new(RefCell::new(BTreeSet::new())),
                    next_assigned: *EXCLUDED.start(),
                    leading_excluded,
                }
            }

            fn bind(&mut self, candidate: Candidate) -> io::Result<Reservation> {
                let port = match candidate {
                    Candidate::Assigned => {
                        self.next_assigned += 1;
                        self.next_assigned
                    }
                    Candidate::At(port) => port,
                };
                // The OS never assigns a port excluded on its own protocol; a named port can be.
                let named = matches!(candidate, Candidate::At(_));
                if self.leading_excluded && named && EXCLUDED.contains(&port) {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                if !self.held.borrow_mut().insert(port) {
                    return Err(io::Error::from(io::ErrorKind::AddrInUse));
                }
                Ok(Reservation(port, Rc::clone(&self.held)))
            }
        }

        fn match_outside_excluded(socket: &Reservation) -> io::Result<u16> {
            if EXCLUDED.contains(&socket.0) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(socket.0)
            }
        }

        #[test]
        fn assigned_candidate_is_used_when_it_matches() {
            let mut model = Model::new(false);
            let pair = reserve_matched_pair(
                PORT_PAIR_ATTEMPTS,
                || panic!("no random candidate needed"),
                |candidate| model.bind(candidate),
                |socket| Ok(socket.0),
            )
            .unwrap();
            assert_eq!(pair.1, *EXCLUDED.start() + 1);
        }

        /// The run-6 failure: every OS-assigned port sits in a block excluded on the matching
        /// protocol. The old logic asked the OS 100 times and exhausted inside the block.
        #[test]
        fn random_fallback_escapes_a_sequential_excluded_block() {
            for leading_excluded in [false, true] {
                let mut model = Model::new(leading_excluded);
                let held = Rc::clone(&model.held);
                let mut candidates = Vec::new();
                let pair = reserve_matched_pair(
                    PORT_PAIR_ATTEMPTS,
                    random_port,
                    |candidate| {
                        candidates.push(candidate);
                        model.bind(candidate)
                    },
                    match_outside_excluded,
                )
                .unwrap();
                assert!(DYNAMIC_PORTS.contains(&pair.1) && !EXCLUDED.contains(&pair.1));
                assert_eq!(candidates[0], Candidate::Assigned);
                assert!(candidates[1..].iter().all(|candidate| {
                    matches!(candidate, Candidate::At(port) if DYNAMIC_PORTS.contains(port))
                }));
                assert_eq!(*held.borrow(), BTreeSet::from([pair.1]));
                drop(pair);
                assert!(held.borrow().is_empty());
            }
        }

        #[test]
        fn random_candidates_cover_the_dynamic_range() {
            let ports: Vec<u16> = (0..10_000).map(|_| random_port()).collect();
            assert!(ports.iter().all(|port| DYNAMIC_PORTS.contains(port)));
            assert!(ports.iter().any(|port| *port < 50_000));
            assert!(ports.iter().any(|port| *port > 64_000));
        }

        #[test]
        fn rejected_candidates_stay_reserved_until_a_pair_is_found() {
            let mut model = Model::new(false);
            let held = Rc::clone(&model.held);
            let mut randoms = [60_001, 60_002].into_iter();
            let mut visited = Vec::new();
            let pair = reserve_matched_pair(
                3,
                || randoms.next().unwrap(),
                |candidate| model.bind(candidate),
                |socket| {
                    visited.push(socket.0);
                    assert_eq!(held.borrow().len(), visited.len());
                    if socket.0 == 60_002 {
                        Ok(socket.0)
                    } else {
                        Err(io::Error::from(io::ErrorKind::AddrInUse))
                    }
                },
            )
            .unwrap();
            assert_eq!(visited, [*EXCLUDED.start() + 1, 60_001, 60_002]);
            assert_eq!(*held.borrow(), BTreeSet::from([60_002]));
            drop(pair);
            assert!(held.borrow().is_empty());
        }

        #[test]
        fn random_bind_failure_costs_only_that_candidate() {
            let mut model = Model::new(true);
            model.next_assigned = 40_000;
            let held = Rc::clone(&model.held);
            // Excluded on the leading protocol, then the held assigned port, then a free one.
            let mut randoms = [56_000, 40_001, 60_000].into_iter();
            let mut matched = Vec::new();
            let pair = reserve_matched_pair(
                4,
                || randoms.next().unwrap(),
                |candidate| model.bind(candidate),
                |socket| {
                    matched.push(socket.0);
                    if socket.0 == 40_001 {
                        Err(io::Error::from(io::ErrorKind::AddrInUse))
                    } else {
                        Ok(socket.0)
                    }
                },
            )
            .unwrap();
            assert_eq!(matched, [40_001, 60_000]);
            assert_eq!(pair.1, 60_000);
            assert_eq!(*held.borrow(), BTreeSet::from([60_000]));
            drop(pair);
            assert!(held.borrow().is_empty());
        }

        #[test]
        fn exhaustion_is_bounded_and_releases_every_candidate() {
            let mut model = Model::new(false);
            let held = Rc::clone(&model.held);
            let mut next = 60_000;
            let mut tries = 0;
            let error = reserve_matched_pair::<_, ()>(
                3,
                || {
                    next += 1;
                    next
                },
                |candidate| {
                    tries += 1;
                    model.bind(candidate)
                },
                |_| {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "UDP excluded",
                    ))
                },
            )
            .unwrap_err();
            assert_eq!(tries, 3);
            assert!(held.borrow().is_empty());
            assert!(error.to_string().contains("3 candidates (3 reserved)"));
            assert!(error.to_string().contains("UDP excluded"));
        }

        #[test]
        fn assigned_bind_failure_is_fatal() {
            let mut tries = 0;
            let error = reserve_matched_pair::<Reservation, ()>(
                3,
                || panic!("no random candidate after a fatal bind"),
                |_| {
                    tries += 1;
                    Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                },
                |_| unreachable!(),
            )
            .unwrap_err();
            assert_eq!(tries, 1);
            assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        }
    }
}

#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod tracing_common {
    use std::sync::Mutex;
    use std::sync::OnceLock;

    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    /// Called with every event the process emits, from whichever thread emits it.
    pub(crate) type EventTap = fn(&tracing::Event<'_>);

    static TAPS: Mutex<Vec<EventTap>> = Mutex::new(Vec::new());

    /// Installs this binary's one process-global subscriber, once: `fmt` output filtered by
    /// `RUST_LOG` (what `tracing_subscriber::fmt::try_init` gave), plus the taps tests add.
    ///
    /// Tests share one process and run in any order, so a test that installs a global subscriber
    /// of its own fails whenever another test installed one first. Every test that needs a global
    /// subscriber comes here instead. False only if something else installed one first.
    pub(crate) fn install_global_subscriber() -> bool {
        static INSTALLED: OnceLock<bool> = OnceLock::new();
        *INSTALLED.get_or_init(|| {
            tracing::subscriber::set_global_default(
                tracing_subscriber::registry()
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_test_writer()
                            .with_filter(EnvFilter::from_default_env()),
                    )
                    .with(Taps),
            )
            .is_ok()
        })
    }

    /// Installs the global subscriber and adds `tap` to it. False if the subscriber is not ours.
    pub(crate) fn add_event_tap(tap: EventTap) -> bool {
        if !install_global_subscriber() {
            return false;
        }
        let Ok(mut taps) = TAPS.lock() else {
            return false;
        };
        if !taps.contains(&tap) {
            taps.push(tap);
        }
        true
    }

    /// Unfiltered, so a tap sees every event whatever `RUST_LOG` says.
    struct Taps;

    impl<S: tracing::Subscriber> Layer<S> for Taps {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            // A copy, so a tap that emits an event cannot deadlock on the lock.
            let taps = match TAPS.lock() {
                Ok(taps) => taps.clone(),
                Err(_poisoned) => return,
            };
            for tap in taps {
                tap(event);
            }
        }
    }
}

#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod aws_common {
    use std::error::Error;
    use std::sync::Arc;

    use aws_sdk_dynamodb::operation::create_table::CreateTableError;
    use aws_sdk_dynamodb::types::AttributeDefinition;
    use aws_sdk_dynamodb::types::GlobalSecondaryIndex;
    use aws_sdk_dynamodb::types::KeySchemaElement;
    use aws_sdk_dynamodb::types::KeyType;
    use aws_sdk_dynamodb::types::Projection;
    use aws_sdk_dynamodb::types::ProjectionType;
    use aws_sdk_dynamodb::types::ProvisionedThroughput;
    use aws_sdk_dynamodb::types::ScalarAttributeType;
    use aws_sdk_s3::operation::create_bucket::CreateBucketError;
    use lore_aws::clients::AwsClientBuilder;
    use lore_aws::clients::HttpClientSettings;
    use lore_aws::dynamodb::DynamoDb;
    use lore_aws::s3::S3;
    use lore_aws::store::immutable_store::FRAGMENTS_DYNAMO_PARTITION_KEY_ATTRIBUTE;
    use lore_aws::store::immutable_store::FRAGMENTS_DYNAMO_SORT_KEY_ATTRIBUTE;
    use lore_aws::store::lock_store::*;
    use lore_aws::store::mutable_store::MUTABLE_STORE_DYNAMO_PARTITION_KEY_ATTRIBUTE;
    use lore_aws::store::mutable_store::MUTABLE_STORE_DYNAMO_SORT_KEY_ATTRIBUTE;
    use lore_revision::util::time::RetryPolicy;
    use tracing::info;
    use tracing::warn;

    pub const LOCKS_TABLE_NAME: &str = "locks-local";
    pub const STORE_BUCKET_NAME: &str = "lore-immutable-store-local";
    pub const MUTABLE_STORE_TABLE_NAME: &str = "lore-mutable-store-local";
    pub const FRAGMENTS_TABLE_NAME: &str = "lore-fragments-local";
    pub const FRAGMENT_STATE_TABLE_NAME: &str = "lore-fragment-state-local";
    pub const FRAGMENT_METADATA_TABLE_NAME: &str = "lore-fragment-metadata-local";

    // NOTE: these credentials are just hardcoded in lore-integration-tests/compose.yaml
    const AWS_ACCESS_KEY_ID: &str = "lorelocal";
    const AWS_SECRET_ACCESS_KEY: &str = "lorelocal";

    /// The endpoint of `DynamoDB` Local: `LORE_INTEGRATION_DYNAMODB_ENDPOINT`, else where
    /// `lore-integration-tests/compose.yaml` runs it.
    pub fn dynamodb_endpoint() -> String {
        std::env::var("LORE_INTEGRATION_DYNAMODB_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9090".to_string())
    }

    pub async fn setup(
        tables: Vec<&str>,
    ) -> Result<(S3, DynamoDb, DynamoDb), Box<dyn Error + 'static>> {
        let _ = crate::common::tracing_common::install_global_subscriber();
        let s3_endpoint = std::env::var("LORE_INTEGRATION_S3_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
        let dynamodb_endpoint = dynamodb_endpoint();

        Ok((
            s3_client(s3_endpoint).await?,
            dynamodb_client(dynamodb_endpoint.clone(), tables.clone()).await?,
            dynamodb_client(dynamodb_endpoint, tables).await?,
        ))
    }

    /// A client of `DynamoDB` Local alone, holding `tables`, with the tracing [`setup`] starts.
    pub async fn dynamodb_setup(tables: Vec<&str>) -> Result<DynamoDb, Box<dyn Error + 'static>> {
        let _ = tracing_subscriber::fmt::try_init();
        dynamodb_client(dynamodb_endpoint(), tables).await
    }

    async fn create_store_bucket(client: &aws_sdk_s3::Client) -> Result<(), Box<dyn Error>> {
        match client
            .create_bucket()
            .bucket(STORE_BUCKET_NAME)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateBucketError::BucketAlreadyOwnedByYou(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the bucket, if it turns out the bucket exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
        }
    }

    async fn s3_client(endpoint_url: String) -> Result<S3, Box<dyn Error + 'static>> {
        let http_settings = HttpClientSettings::default();

        // Set up AWS client.
        let creds = aws_sdk_s3::config::Credentials::new(
            AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY,
            None,
            None,
            "test",
        );

        let client = AwsClientBuilder::builder()
            .with_http_settings(&http_settings)
            .with_credentials_provider(creds)
            .region("us-east-1")
            .endpoint(endpoint_url)
            .build_config()
            .await
            .s3()
            .build()
            .await?;

        match client.bucket_exists(STORE_BUCKET_NAME.to_string()).await {
            Ok(exists) => {
                if !exists {
                    info!("Bucket {STORE_BUCKET_NAME} does not exist, creating...");
                    create_store_bucket(client.sdk_client()).await?;
                }

                Ok(client)
            }
            Err(e) => {
                warn!("Failed to check if bucket exists: {e:?}");
                Err(e.into())
            }
        }
    }

    async fn create_locks_table(client: &aws_sdk_dynamodb::Client) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(LOCKS_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(HASH_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(REPO_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(BRANCH_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(REPO_BRANCH_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(OWNER_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::S))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(DESC_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::S))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(HASH_KEY)
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(REPO_BRANCH_KEY)
                    .set_key_type(Some(KeyType::Range))
                    .build()?,
            )
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(OWNER_REPO_BRANCH_GSI)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(OWNER_KEY)
                            .set_key_type(Some(KeyType::Hash))
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(REPO_BRANCH_KEY)
                            .set_key_type(Some(KeyType::Range))
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .provisioned_throughput(
                        ProvisionedThroughput::builder()
                            .set_read_capacity_units(Some(5000))
                            .set_write_capacity_units(Some(5000))
                            .build()?,
                    )
                    .build()?,
            )
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(REPO_BRANCH_GSI)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(REPO_KEY)
                            .set_key_type(Some(KeyType::Hash))
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(BRANCH_KEY)
                            .set_key_type(Some(KeyType::Range))
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .provisioned_throughput(
                        ProvisionedThroughput::builder()
                            .set_read_capacity_units(Some(5000))
                            .set_write_capacity_units(Some(5000))
                            .build()?,
                    )
                    .build()?,
            )
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(REPO_BRANCH_DESC_GSI)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(REPO_BRANCH_KEY)
                            .set_key_type(Some(KeyType::Hash))
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(DESC_KEY)
                            .set_key_type(Some(KeyType::Range))
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .provisioned_throughput(
                        ProvisionedThroughput::builder()
                            .set_read_capacity_units(Some(5000))
                            .set_write_capacity_units(Some(5000))
                            .build()?,
                    )
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_store_table(client: &aws_sdk_dynamodb::Client) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(MUTABLE_STORE_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Range))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_fragments_table(
        client: &aws_sdk_dynamodb::Client,
    ) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(FRAGMENTS_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Range))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_fragment_state_table(
        client: &aws_sdk_dynamodb::Client,
    ) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(FRAGMENT_STATE_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hash")
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hash")
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_fragment_metadata_table(
        client: &aws_sdk_dynamodb::Client,
    ) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(FRAGMENT_METADATA_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hash")
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hash")
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    pub(crate) async fn dynamodb_client(
        endpoint_url: String,
        tables: Vec<&str>,
    ) -> Result<DynamoDb, Box<dyn Error + 'static>> {
        dynamodb_client_with_unprocessed_keys_retry(endpoint_url, tables, None).await
    }

    /// Connects to `DynamoDB` at `endpoint_url`, creating any of `tables` that is missing. The
    /// client resends unprocessed `BatchGetItem` keys with `unprocessed_keys_retry`, or with the
    /// client default when it is `None`.
    pub(crate) async fn dynamodb_client_with_unprocessed_keys_retry(
        endpoint_url: String,
        tables: Vec<&str>,
        unprocessed_keys_retry: Option<RetryPolicy>,
    ) -> Result<DynamoDb, Box<dyn Error + 'static>> {
        let http_settings = HttpClientSettings::default();

        let creds = aws_sdk_dynamodb::config::Credentials::new(
            AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY,
            None,
            None,
            "test",
        );

        let client = AwsClientBuilder::builder()
            .with_http_settings(&http_settings)
            .with_credentials_provider(creds)
            .region("us-east-2")
            .endpoint(endpoint_url)
            .build_config()
            .await
            .maybe_unprocessed_keys_retry(unprocessed_keys_retry)
            .dynamodb()
            .build()
            .await?;

        for table_name in tables {
            match client.table_exists(&Arc::from(table_name)).await {
                Ok(exists) => {
                    if !exists {
                        match table_name {
                            MUTABLE_STORE_TABLE_NAME => {
                                create_store_table(client.sdk_client()).await?;
                            }
                            FRAGMENTS_TABLE_NAME => {
                                create_fragments_table(client.sdk_client()).await?;
                            }
                            FRAGMENT_STATE_TABLE_NAME => {
                                create_fragment_state_table(client.sdk_client()).await?;
                            }
                            FRAGMENT_METADATA_TABLE_NAME => {
                                create_fragment_metadata_table(client.sdk_client()).await?;
                            }
                            LOCKS_TABLE_NAME => create_locks_table(client.sdk_client()).await?,
                            _ => {
                                return Err(
                                    anyhow::anyhow!("Invalid table name: {table_name}").into()
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to check if table exists: {e:?}");
                    return Err(e.into());
                }
            }
        }

        Ok(client)
    }
}
