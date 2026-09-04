// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// WP-120 Phase 3: gRPC mutation dispatch-loss fixtures.
//
// [CLIENT]-class, mirroring `quic_session_rebind_test.rs`'s own classification: this exercises
// `lore-transport`'s gRPC client (`GRPCStorage`, `GRPCRepository`, `with_reconnect_classified`)
// against a real, in-process loopback gRPC server. The minimal server implementations built here
// are test-only scaffolding, not a change to any production crate.
//
// Two shapes of "dispatched, response lost" exist on this transport and both need their own
// proof, because they go through different client-side code:
//
// - **Streaming** (`Put`/`PutResolved`/`Copy`/`Get`/`GetMetadata`/`GetResolved`): the request
//   reaches the server over a long-lived bidi stream; the response stream can end (cleanly or
//   with an error) without ever answering a specific in-flight item. `StorageService`'s internal
//   `StreamCache::request` used to reissue the SAME payload on a fresh stream whenever this
//   happened, indistinguishable from "never sent" -- exactly the redispatch WP-120's contract
//   forbids for a `MutableNoReplay` verb. `dispatched_put_is_never_reissued_after_the_stream_ends_without_answering`
//   is the discriminating regression test for that: it counts how many times the SERVER actually
//   read a `Put` request, not just how many times the client's call returned.
// - **Unary** (`RepositoryService`/`RevisionService`/`LockService`/`AdminService` mutations): the
//   request is a single RPC through `with_reconnect_classified`, which has no equivalent
//   "payload came back unsent" signal -- gRPC gives this layer no dispatch-state proof the way
//   QUIC's own write boundary does. `a_unary_mutation_whose_connection_dies_before_answering_surfaces_as_outcome_unknown`
//   is the discriminating test for whether a genuine connection death (not a normal
//   `Code::Unavailable`-shaped failure, but the server process disappearing mid-request) still
//   reaches the caller as the typed public error rather than falling through as a bare `Internal`.

#[cfg(all(test, feature = "grpc_integration_tests"))]
mod grpc_mutation_dispatch_loss_tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use lore_proto::lore::environment::v1 as environment_v1;
    use lore_proto::lore::environment::v1::environment_service_server::EnvironmentService as EnvironmentServiceV1;
    use lore_proto::lore::environment::v1::environment_service_server::EnvironmentServiceServer;
    use lore_proto::lore::model::v1 as model_v1;
    use lore_proto::lore::repository::v1 as repository_v1;
    use lore_proto::lore::repository::v1::repository_service_server::RepositoryService as RepositoryServiceV1;
    use lore_proto::lore::repository::v1::repository_service_server::RepositoryServiceServer;
    use lore_proto::lore::storage::v1 as storage_v1;
    use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
    use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
    use lore_revision::lore::RepositoryId;
    use tokio_stream::StreamExt;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::Request;
    use tonic::Response;
    use tonic::Status;
    use tonic::Streaming;

    type ResponseStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send>>;

    const SIGNAL_TIMEOUT: Duration = Duration::from_secs(10);

    // ---------------------------------------------------------------------------------------
    // Connect-time scaffolding, required by both servers below.
    // ---------------------------------------------------------------------------------------

    /// `lore_transport::connect` calls `EnvironmentService::EnvironmentGet` before it hands back
    /// a connection, to learn the auth URL. A server that does not implement it answers
    /// `Unimplemented`, which the client classifies as `NotSupported` and fails the connect on —
    /// so without this stub neither test below ever reaches its own assertions, and both fail
    /// during setup for a reason that has nothing to do with what they are testing.
    ///
    /// An empty `Environment` is exactly what these tests want: it leaves the auth URL blank, so
    /// `connect` skips the token exchange and goes straight to the storage or repository RPC
    /// under test.
    struct MinimalEnvironmentServer;

    #[tonic::async_trait]
    impl EnvironmentServiceV1 for MinimalEnvironmentServer {
        async fn environment_get(
            &self,
            _request: Request<environment_v1::EnvironmentGetRequest>,
        ) -> Result<Response<environment_v1::EnvironmentGetResponse>, Status> {
            Ok(Response::new(environment_v1::EnvironmentGetResponse {
                environment: Some(environment_v1::Environment::default()),
            }))
        }
    }

    /// A byte-level proxy the test can sever, sitting between the client and the server.
    ///
    /// The obvious severing mechanism — abort the task running `serve_with_incoming` — does not
    /// work, and the failure is silent rather than loud. Measured on this rig: with the server
    /// task aborted, the client's `delete` call was still pending 90 seconds later. Aborting the
    /// accept loop does not reach connections tonic has already accepted, so the hanging handler
    /// stays alive and the client waits on a socket nobody closed.
    ///
    /// Severing the socket is both what actually works and what a real network failure does. The
    /// client's request has already been dispatched and read by the handler when the halves are
    /// dropped, which is exactly the case under test: an answer that will never arrive.
    async fn spawn_severable_proxy(
        upstream: std::net::SocketAddr,
    ) -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
        let (sever, _) = tokio::sync::watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_sever = sever.clone();
        #[allow(clippy::disallowed_methods)] // Test-local proxy task.
        tokio::spawn(async move {
            loop {
                let mut accept_signal = accept_sever.subscribe();
                let accepted = tokio::select! {
                    _ = accept_signal.wait_for(|severed| *severed) => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut downstream, _)) = accepted else {
                    break;
                };
                let Ok(mut origin) = tokio::net::TcpStream::connect(upstream).await else {
                    break;
                };
                let mut conn_signal = accept_sever.subscribe();
                #[allow(clippy::disallowed_methods)] // Test-local proxy task.
                tokio::spawn(async move {
                    tokio::select! {
                        _ = conn_signal.wait_for(|severed| *severed) => {}
                        _ = tokio::io::copy_bidirectional(&mut downstream, &mut origin) => {}
                    }
                    // Both halves drop here. That is the sever.
                });
            }
        });

        (addr, sever)
    }

    // ---------------------------------------------------------------------------------------
    // Streaming: `StorageService::Put` loses its response after the server has already read it.
    // ---------------------------------------------------------------------------------------

    /// Reads exactly one `Put` request off the stream, counts it, then ends the response stream
    /// with nothing -- no in-band status, no answer. From the client's `pump_responses` this
    /// looks exactly like a connection that died after the request reached the server: the
    /// reader task sees the stream end and fails every outstanding request as `Disconnected`
    /// (`storage_client.rs`'s own doc comment: "the ordinary ways a connection dies arrive as
    /// Internal or Cancelled... neither of which a caller would otherwise retry" -- which is
    /// exactly why that layer normalizes to `Disconnected` rather than forwarding the raw code).
    /// Every other RPC on this trait is unused by this file and returns `Unimplemented`.
    struct LossyPutServer {
        streams_opened: Arc<AtomicUsize>,
        requests_read: Arc<AtomicUsize>,
    }

    #[tonic::async_trait]
    impl StorageServiceV1 for LossyPutServer {
        type GetStream = ResponseStream<storage_v1::GetResponse>;
        async fn get(
            &self,
            _request: Request<Streaming<model_v1::Address>>,
        ) -> Result<Response<Self::GetStream>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        type GetMetadataStream = ResponseStream<storage_v1::GetResponse>;
        async fn get_metadata(
            &self,
            _request: Request<Streaming<model_v1::Address>>,
        ) -> Result<Response<Self::GetMetadataStream>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        type GetResolvedStream = ResponseStream<storage_v1::GetResolvedResponse>;
        async fn get_resolved(
            &self,
            _request: Request<Streaming<storage_v1::GetResolvedRequest>>,
        ) -> Result<Response<Self::GetResolvedStream>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        type PutResolvedStream = ResponseStream<storage_v1::PutResolvedResponse>;
        async fn put_resolved(
            &self,
            _request: Request<Streaming<storage_v1::PutResolvedRequest>>,
        ) -> Result<Response<Self::PutResolvedStream>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        type PutStream = ResponseStream<storage_v1::PutResponse>;
        async fn put(
            &self,
            request: Request<Streaming<storage_v1::PutRequest>>,
        ) -> Result<Response<Self::PutStream>, Status> {
            self.streams_opened.fetch_add(1, Ordering::SeqCst);
            let mut requests = request.into_inner();
            if let Some(Ok(_req)) = requests.next().await {
                self.requests_read.fetch_add(1, Ordering::SeqCst);
            }
            // The request was read (dispatched to the server); no answer is ever produced. An
            // empty stream ends the RPC immediately with no item and no error -- the same shape
            // a real severed connection leaves on the client's reader task.
            let empty: ResponseStream<storage_v1::PutResponse> = Box::pin(tokio_stream::empty());
            Ok(Response::new(empty))
        }

        type CopyStream = ResponseStream<storage_v1::CopyResponse>;
        async fn copy(
            &self,
            _request: Request<Streaming<storage_v1::CopyRequest>>,
        ) -> Result<Response<Self::CopyStream>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn query(
            &self,
            _request: Request<storage_v1::QueryRequest>,
        ) -> Result<Response<storage_v1::QueryResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn verify(
            &self,
            _request: Request<storage_v1::VerifyRequest>,
        ) -> Result<Response<storage_v1::VerifyResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn mutable_load(
            &self,
            _request: Request<storage_v1::MutableLoadRequest>,
        ) -> Result<Response<storage_v1::MutableLoadResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn mutable_store(
            &self,
            _request: Request<storage_v1::MutableStoreRequest>,
        ) -> Result<Response<storage_v1::MutableStoreResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn mutable_compare_and_swap(
            &self,
            _request: Request<storage_v1::MutableCompareAndSwapRequest>,
        ) -> Result<Response<storage_v1::MutableCompareAndSwapResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }
    }

    async fn start_lossy_put_server() -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let streams_opened = Arc::new(AtomicUsize::new(0));
        let requests_read = Arc::new(AtomicUsize::new(0));
        let server = LossyPutServer {
            streams_opened: streams_opened.clone(),
            requests_read: requests_read.clone(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        #[allow(clippy::disallowed_methods)] // Test-local server task.
        let handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(StorageServiceServer::new(server))
                .add_service(EnvironmentServiceServer::new(MinimalEnvironmentServer))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        (addr, streams_opened, requests_read, handle)
    }

    /// The discriminating regression test for WP-120 Phase 3's `StreamCache::request` fix. A Put
    /// whose response is lost AFTER the server genuinely read it must surface as
    /// `ProtocolError::OutcomeUnknown` to the caller, and the server must have seen exactly ONE
    /// `Put` stream carrying exactly ONE request -- proving `MAX_STREAM_REISSUES`'s reconnect
    /// loop never fires for a dispatched-then-lost mutation, only for a genuinely undispatched
    /// one.
    #[tokio::test]
    async fn dispatched_put_is_never_reissued_after_the_stream_ends_without_answering()
    -> Result<(), Box<dyn std::error::Error>> {
        let (addr, streams_opened, requests_read, _server) = start_lossy_put_server().await;

        let connection = lore_transport::connect(
            &format!("grpc://{addr}"),
            "",
            RepositoryId::default(),
            1,
            "",
            "",
        )
        .await?;
        let storage = connection.storage().await?;

        let session_id = storage
            .session_start(RepositoryId::default(), "dispatch-loss-put")
            .await?;
        let (fragment, address, payload) = lore_revision::fragment::generate_random();

        let result = storage
            .put(session_id, address, fragment, Some(payload))
            .await;

        let error = result.expect_err(
            "a Put whose response is lost after the server read it must not resolve as success",
        );
        assert!(
            error.is_outcome_unknown(),
            "expected ProtocolError::OutcomeUnknown for a dispatched-then-lost Put, got {error:?}"
        );

        assert_eq!(
            streams_opened.load(Ordering::SeqCst),
            1,
            "exactly one Put stream must have been opened -- a reissue would open a second"
        );
        assert_eq!(
            requests_read.load(Ordering::SeqCst),
            1,
            "exactly one Put request must have reached the server -- a reissue would resend the \
             same payload on a fresh stream, which the contract forbids for a dispatched-then-\
             lost mutation"
        );

        Ok(())
    }

    // ---------------------------------------------------------------------------------------
    // Unary: a mutation RPC whose underlying connection disappears entirely before answering.
    // ---------------------------------------------------------------------------------------

    /// Reports exactly when the server received the delete, then hangs forever. The test aborts
    /// the whole server task once it has that signal, which severs the TCP connection out from
    /// under the still-pending unary call -- the unary equivalent of severing a QUIC/streaming
    /// response after real dispatch. Every other RPC on this trait returns `Unimplemented`.
    struct HangingDeleteServer {
        dispatched: Arc<AtomicUsize>,
        notify_dispatched: Arc<tokio::sync::Notify>,
    }

    #[tonic::async_trait]
    impl RepositoryServiceV1 for HangingDeleteServer {
        async fn repository_create(
            &self,
            _request: Request<repository_v1::RepositoryCreateRequest>,
        ) -> Result<Response<repository_v1::RepositoryCreateResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn repository_delete(
            &self,
            _request: Request<repository_v1::RepositoryDeleteRequest>,
        ) -> Result<Response<repository_v1::RepositoryDeleteResponse>, Status> {
            self.dispatched.fetch_add(1, Ordering::SeqCst);
            self.notify_dispatched.notify_one();
            // Never returns. The test severs the connection by aborting the server task; the
            // resulting client-side error is exactly what a real connection death produces,
            // whatever tonic code that turns out to be.
            std::future::pending::<()>().await;
            unreachable!("the server task is aborted before this future can ever resolve")
        }

        async fn repository_get(
            &self,
            _request: Request<repository_v1::RepositoryGetRequest>,
        ) -> Result<Response<repository_v1::RepositoryGetResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        type RepositoryListStream = ResponseStream<repository_v1::RepositoryListResponse>;
        async fn repository_list(
            &self,
            _request: Request<repository_v1::RepositoryListRequest>,
        ) -> Result<Response<Self::RepositoryListStream>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn repository_metadata_get(
            &self,
            _request: Request<repository_v1::RepositoryMetadataGetRequest>,
        ) -> Result<Response<repository_v1::RepositoryMetadataGetResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn repository_metadata_set(
            &self,
            _request: Request<repository_v1::RepositoryMetadataSetRequest>,
        ) -> Result<Response<repository_v1::RepositoryMetadataSetResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn repository_storage_stats(
            &self,
            _request: Request<repository_v1::RepositoryStorageStatsRequest>,
        ) -> Result<Response<repository_v1::RepositoryStorageStatsResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }
    }

    /// The discriminating test for the unary half of Phase 3. `with_reconnect_classified` has no
    /// positive dispatch-state proof the way the streaming send does -- it can only branch on
    /// `ProtocolError::Disconnected`. This proves that branch is actually reached for a real
    /// connection death during a unary mutation, not just for the `Code::Unavailable` shape a
    /// hand-built `tonic::Status` would produce.
    #[tokio::test]
    async fn a_unary_mutation_whose_connection_dies_before_answering_surfaces_as_outcome_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let notify_dispatched = Arc::new(tokio::sync::Notify::new());
        let server = HangingDeleteServer {
            dispatched: dispatched.clone(),
            notify_dispatched: notify_dispatched.clone(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        #[allow(clippy::disallowed_methods)] // Test-local server task.
        let _server_task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(RepositoryServiceServer::new(server))
                .add_service(EnvironmentServiceServer::new(MinimalEnvironmentServer))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        });

        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // The client talks to the proxy, not to the server, so the test can cut the socket
        // underneath a dispatched request. See `spawn_severable_proxy` for why aborting the
        // server task is not enough.
        let (proxy_addr, sever) = spawn_severable_proxy(addr).await;

        let connection = lore_transport::connect(
            &format!("grpc://{proxy_addr}"),
            "",
            RepositoryId::default(),
            1,
            "",
            "",
        )
        .await?;
        let repository = connection.repository().await?;

        #[allow(clippy::disallowed_methods)]
        let delete_task =
            tokio::spawn(async move { repository.delete(RepositoryId::default()).await });

        tokio::time::timeout(SIGNAL_TIMEOUT, notify_dispatched.notified())
            .await
            .expect("the server never reported receiving the delete request");
        assert_eq!(
            dispatched.load(Ordering::SeqCst),
            1,
            "exactly one delete must have reached the server before the connection is severed"
        );

        // Sever the connection at the socket, with the delete already dispatched and read by the
        // handler and no answer on the way back.
        sever.send_replace(true);

        let result = tokio::time::timeout(SIGNAL_TIMEOUT, delete_task)
            .await
            .expect("the delete call must return after the connection dies, not hang forever")
            .expect("the client task must not panic");

        let error =
            result.expect_err("a delete whose connection died before answering must not succeed");
        assert!(
            error.is_outcome_unknown(),
            "a real connection death during a dispatched unary mutation must surface as \
             ProtocolError::OutcomeUnknown, not silently fall through to Internal/Cancelled; got \
             {error:?}"
        );

        Ok(())
    }
}
