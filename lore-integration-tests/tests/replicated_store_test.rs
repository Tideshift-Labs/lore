// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#[cfg(all(test, feature = "integration_tests"))]
mod replicated_store_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Weak;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use async_trait::async_trait;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_base::types::Partition;
    use lore_revision::fragment;
    use lore_revision::util::time::RetryPolicy;
    use lore_server::protocol::replication_store::copy::ImmutableCopy;
    use lore_server::protocol::replication_store::get::Get;
    use lore_server::protocol::replication_store::get_metadata::GetMetadata;
    use lore_server::protocol::replication_store::obliterate::Obliterate;
    use lore_server::protocol::replication_store::obliterate::ObliterateResponse;
    use lore_server::protocol::replication_store::put::Put;
    use lore_server::protocol::replication_store::query::Query;
    use lore_server::protocol::replication_store::query::QueryResponse;
    use lore_server::quic::quinn::QuinnConfigBuilder;
    use lore_server::quic::quinn::QuinnServer;
    use lore_server::quic::replication_store_service::client::ReplicationStoreClient;
    use lore_server::quic::replication_store_service::client::ReplicationStoreClientError;
    use lore_server::quic::replication_store_service::client::StoreClient;
    use lore_server::quic::replication_store_service::client_container::ClientContainerConfig;
    use lore_server::quic::replication_store_service::client_container::ClientFactory;
    use lore_server::quic::replication_store_service::client_container::QuicClientFactory;
    use lore_server::quic::tests::TestHandlerFactory;
    use lore_server::store::replicated_store::ReplicatedStore;
    use lore_storage::ImmutableStore;
    use lore_storage::KeyType;
    use lore_storage::KeyValueStream;
    use lore_storage::MutableStore;
    use lore_storage::StoreError;
    use lore_storage::StoreGetData;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_transport::OutcomeUnknown;
    use lore_transport::ProtocolError;
    use lore_transport::connection::Connection;
    use lore_transport::connection::SuppliedCredentials;
    use lore_transport::quic::client::CertificateSettings;
    use lore_transport::quic::client::ConnectionStats;
    use lore_transport::quic::storage_service::client::StorageClient;
    use lore_transport::replay::MutableOutcome;
    use lore_transport::traits::Storage;

    use crate::setup_execution;

    /// Starts a QUIC replication server backed by a local immutable store and returns
    /// `(replicated_store, _server)` where `replicated_store` is the [`ReplicatedStore`]
    /// client connected to it. The server is kept alive for as long as `_server` is held.
    async fn start_replication_server()
    -> (Arc<ReplicatedStore<ReplicationStoreClient>>, QuinnServer) {
        let backend_immutable = lore_storage::local::immutable_store::create(
            None::<&str>,
            ImmutableStoreCreateOptions::none(),
            false,
            ImmutableStoreSettings {
                // The ReplicatedStore declares isolates_partitions() → true, so the server
                // it talks to must also isolate — otherwise partition-matched results would
                // pass through where the battery expects none.
                isolate_partitions: true,
                ..Default::default()
            },
        )
        .await
        .expect("backend immutable store");

        let backend_mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            backend_immutable.clone(),
        )
        .await
        .expect("backend mutable store");

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let addr: SocketAddr = udp.local_addr().expect("udp local addr");

        let (cert_file, pkey_file, _ca) =
            lore_server::quic::tests::server_certs().expect("test certificate paths");

        let quic = QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(TestHandlerFactory::new(
                    backend_immutable,
                    backend_mutable,
                )))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start");

        // Plain `quic://` rather than `quics://` so the client skips verification of the
        // self-signed test certificate.
        let remote_url = format!("quic://127.0.0.1:{}", addr.port());

        let factory = QuicClientFactory::new(
            remote_url,
            CertificateSettings {
                custom_ca: None,
                client: None,
            },
        );

        let container_config = ClientContainerConfig {
            regenerate_retry_policy: RetryPolicy::builder()
                .with_initial_backoff_millis(50)
                .with_max_backoff_millis(1_000)
                .with_limit(10)
                .build(),
            connection_lost_sleep: Duration::from_millis(100),
        };

        let store = ReplicatedStore::new(
            Arc::new(factory),
            container_config,
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .await
        .expect("ReplicatedStore creation should succeed");

        (store, quic)
    }

    fn start_storage_service_server(
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
    ) -> (QuinnServer, SocketAddr) {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let addr = udp.local_addr().expect("udp local addr");
        let (cert_file, pkey_file, _ca) =
            lore_server::quic::tests::server_certs().expect("test certificate paths");
        let server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(TestHandlerFactory::new(immutable, mutable)))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start");
        (server, addr)
    }

    async fn connect_storage_client(
        addr: SocketAddr,
        partition: Partition,
    ) -> (StorageClient, u32) {
        let credentials = Arc::new(SuppliedCredentials::default());
        let client = StorageClient::connect(
            Weak::<Connection>::new(),
            &format!("quic://127.0.0.1:{}", addr.port()),
            String::new(),
            "",
            "",
            partition,
            &credentials,
        )
        .await
        .expect("storage client connection");
        let session_id = client
            .session_start(partition, "outcome-unknown")
            .await
            .expect("storage session start");
        (client, session_id)
    }

    /// The contract, against the replicated store backed by a live QUIC replication service.
    ///
    /// Unlike the unit test that exercises the replicated store against a mock client, this test
    /// wires a real connection so that the full path — protocol encoding, network dispatch,
    /// server-side handler, and response decoding — is exercised against the battery.
    ///
    /// The server is configured the way a real one is, isolating partitions, because the pair
    /// satisfies the client store's declared read scope only if the server it talks to answers
    /// exact associations.
    #[tokio::test]
    async fn satisfies_the_immutable_store_contract() {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (replicated_store, _server) = start_replication_server().await;

                lore_storage::conformance::verify_immutable_store(
                    replicated_store,
                    lore_storage::conformance::Capabilities::new("ReplicatedStore/quic")
                        .over_wire(),
                )
                .await;
            })
            .await;
    }

    struct OutcomeUnknownClient {
        put_calls: Arc<AtomicUsize>,
        copy_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl StoreClient for OutcomeUnknownClient {
        async fn connection_stats(&self) -> Option<ConnectionStats> {
            None
        }

        async fn put(&self, _request: Put) -> Result<(), ReplicationStoreClientError> {
            self.put_calls.fetch_add(1, Ordering::Relaxed);
            Err(ReplicationStoreClientError::OutcomeUnknown(
                OutcomeUnknown { command: "put" },
            ))
        }

        async fn obliterate(
            &self,
            _request: Obliterate,
        ) -> Result<ObliterateResponse, ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn get(&self, _request: Get) -> Result<StoreGetData, ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn get_metadata(
            &self,
            _request: GetMetadata,
        ) -> Result<StoreGetData, ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn local_put(&self, _request: Put) -> Result<(), ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn local_get(
            &self,
            _request: Get,
        ) -> Result<StoreGetData, ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn local_get_metadata(
            &self,
            _request: GetMetadata,
        ) -> Result<StoreGetData, ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn query(
            &self,
            _request: Query,
        ) -> Result<QueryResponse, ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn local_query(
            &self,
            _request: Query,
        ) -> Result<QueryResponse, ReplicationStoreClientError> {
            unreachable!("the outcome-unknown fixture only drives put")
        }

        async fn copy(&self, _request: ImmutableCopy) -> Result<(), ReplicationStoreClientError> {
            self.copy_calls.fetch_add(1, Ordering::Relaxed);
            Err(ReplicationStoreClientError::OutcomeUnknown(
                OutcomeUnknown { command: "copy" },
            ))
        }
    }

    struct OutcomeUnknownFactory {
        put_calls: Arc<AtomicUsize>,
        copy_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ClientFactory for OutcomeUnknownFactory {
        type Output = OutcomeUnknownClient;

        async fn make_client(
            &self,
            _initial_cwnd: Option<u64>,
        ) -> Result<Self::Output, ProtocolError> {
            Ok(OutcomeUnknownClient {
                put_calls: self.put_calls.clone(),
                copy_calls: self.copy_calls.clone(),
            })
        }
    }

    /// A peer's typed ambiguous outcome must cross the complete storage-service boundary as an
    /// ambiguous client outcome, not as an answered error that the session layer could replay.
    /// `ReplicatedStore` is the real immutable backend of `StorageServiceV4`; the concrete QUIC
    /// client opens a session and sends a real Put frame through it.
    #[tokio::test]
    async fn peer_outcome_unknown_is_not_exposed_as_a_replayable_answered_error() {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let put_calls = Arc::new(AtomicUsize::new(0));
                let copy_calls = Arc::new(AtomicUsize::new(0));
                let factory = OutcomeUnknownFactory {
                    put_calls: put_calls.clone(),
                    copy_calls: copy_calls.clone(),
                };
                let store = ReplicatedStore::new(
                    Arc::new(factory),
                    ClientContainerConfig {
                        regenerate_retry_policy: RetryPolicy::builder()
                            .with_initial_backoff_millis(1)
                            .with_max_backoff_millis(1)
                            .with_limit(1)
                            .build(),
                        connection_lost_sleep: Duration::from_millis(1),
                    },
                    Duration::from_secs(60),
                    Duration::from_secs(60),
                )
                .await
                .expect("ReplicatedStore creation should succeed");

                let local_immutable = lore_storage::local::immutable_store::create(
                    None::<&str>,
                    ImmutableStoreCreateOptions::none(),
                    false,
                    ImmutableStoreSettings::default(),
                )
                .await
                .expect("local immutable store");
                let local_mutable = lore_storage::local::mutable_store::create(
                    None::<&str>,
                    lore_storage::MutableStoreSettings::default(),
                    local_immutable,
                )
                .await
                .expect("local mutable store");

                let partition = Partition::from([0x51; 16]);
                let (_server, addr) = start_storage_service_server(store, local_mutable);
                let (client, session_id) = connect_storage_client(addr, partition).await;

                let (fragment, address, payload) = fragment::generate_random();
                let outcome = client
                    .put_outcome(session_id, address, fragment, Some(payload))
                    .await
                    .expect("the typed wire outcome is not a transport error");

                assert!(matches!(outcome, MutableOutcome::Unknown(_)));
                assert_eq!(
                    put_calls.load(Ordering::Relaxed),
                    1,
                    "the storage service must issue the peer mutation exactly once"
                );

                let copy_outcome = client
                    .copy_outcome(session_id, partition, address, Context::from([0x53; 16]))
                    .await
                    .expect("the typed Copy wire outcome is not a transport error");
                assert!(matches!(copy_outcome, MutableOutcome::Unknown(_)));
                assert_eq!(
                    copy_calls.load(Ordering::Relaxed),
                    1,
                    "the storage service must issue the peer Copy exactly once"
                );
            })
            .await;
    }

    #[derive(Default)]
    struct OutcomeUnknownMutableStore {
        store_calls: AtomicUsize,
        compare_and_swap_calls: AtomicUsize,
    }

    impl OutcomeUnknownMutableStore {
        fn unknown(command: &'static str) -> StoreError {
            StoreError::internal_with_context(
                OutcomeUnknown { command },
                "the backing store cannot prove the mutation outcome",
            )
        }
    }

    #[async_trait]
    impl MutableStore for OutcomeUnknownMutableStore {
        async fn load(
            self: Arc<Self>,
            _partition: Partition,
            _key: Hash,
            _key_type: KeyType,
        ) -> Result<Hash, StoreError> {
            unreachable!("the outcome-unknown fixture only drives mutable writes")
        }

        async fn store(
            self: Arc<Self>,
            _partition: Partition,
            _key: Hash,
            _value: Hash,
            _key_type: KeyType,
        ) -> Result<(), StoreError> {
            self.store_calls.fetch_add(1, Ordering::Relaxed);
            Err(Self::unknown("mutable_store"))
        }

        async fn compare_and_swap(
            self: Arc<Self>,
            _partition: Partition,
            _key: Hash,
            _expected: Hash,
            _value: Hash,
            _key_type: KeyType,
        ) -> Result<Hash, StoreError> {
            self.compare_and_swap_calls.fetch_add(1, Ordering::Relaxed);
            Err(Self::unknown("mutable_compare_and_swap"))
        }

        async fn list(
            self: Arc<Self>,
            _partition: Partition,
            _key_type: KeyType,
        ) -> Result<KeyValueStream, StoreError> {
            unreachable!("the outcome-unknown fixture only drives mutable writes")
        }

        async fn flush(self: Arc<Self>, _sync_data: bool) -> Result<(), StoreError> {
            unreachable!("the outcome-unknown fixture only drives mutable writes")
        }
    }

    /// StorageServiceV4 must preserve a backing store's typed ambiguity for both mutable wire
    /// operations. An answered `OutcomeUnknown` is a final typed result, never retry authority.
    #[tokio::test]
    async fn mutable_backing_outcome_unknown_crosses_the_real_wire_once_per_operation() {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let immutable = lore_storage::local::immutable_store::create(
                    None::<&str>,
                    ImmutableStoreCreateOptions::none(),
                    false,
                    ImmutableStoreSettings::default(),
                )
                .await
                .expect("local immutable store");
                let mutable = Arc::new(OutcomeUnknownMutableStore::default());
                let partition = Partition::from([0x61; 16]);
                let (_server, addr) = start_storage_service_server(immutable, mutable.clone());
                let (client, session_id) = connect_storage_client(addr, partition).await;

                let store_outcome = client
                    .mutable_store_outcome(
                        session_id,
                        Hash::from([0x62; 32]),
                        Hash::from([0x63; 32]),
                        KeyType::Untyped,
                    )
                    .await
                    .expect("MutableStore ambiguity is a typed wire outcome");
                assert!(matches!(store_outcome, MutableOutcome::Unknown(_)));
                assert_eq!(
                    mutable.store_calls.load(Ordering::Relaxed),
                    1,
                    "MutableStore must reach its backing store exactly once"
                );

                let compare_and_swap_outcome = client
                    .mutable_compare_and_swap_outcome(
                        session_id,
                        Hash::from([0x64; 32]),
                        Hash::from([0x65; 32]),
                        Hash::from([0x66; 32]),
                        KeyType::Untyped,
                    )
                    .await
                    .expect("MutableCas ambiguity is a typed wire outcome");
                assert!(matches!(
                    compare_and_swap_outcome,
                    MutableOutcome::Unknown(_)
                ));
                assert_eq!(
                    mutable.compare_and_swap_calls.load(Ordering::Relaxed),
                    1,
                    "MutableCas must reach its backing store exactly once"
                );
            })
            .await;
    }
}
