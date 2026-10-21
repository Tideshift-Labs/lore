// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the public gRPC listener closes at the shutdown
//! signal, not when the last connection does. tonic alone keeps the listener
//! open until every served connection closes, so while one long stream holds an
//! old connection, a new connect completes in the kernel and waits in the
//! backlog, never handshaken, until that stream ends. Behind a front that is a
//! request hung until the force-close, then an unknown outcome. Here a new
//! connect must be refused while the old stream is still in flight.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use lore_proto::lore::environment::v1::EnvironmentGetRequest;
use lore_proto::lore::environment::v1::EnvironmentGetResponse;
use lore_proto::model::ReplicationPutRequest;
use lore_proto::rpc::replication_service_client::ReplicationServiceClient;
use lore_revision::environment::EnvironmentConfig;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
use lore_server::grpc::GrpcInternalServerBuilder;
use lore_server::grpc::server::FeatureSettings;
use lore_server::grpc::server::GrpcServerBuilder;
use lore_server::grpc::server::GrpcTimeouts;
use lore_server::grpc::server::serve_maintenance;
use lore_server::hooks::HookDispatcher;
use lore_server::legacy::rpc::storage_service_client::StorageServiceClient;
use lore_server::settings::BaselineAccess;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tokio::io::AsyncReadExt;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

use crate::store::test_support::test_store_create;

/// Long enough for a refused loopback connect on Windows, which retries the
/// SYN for about two seconds before it reports the refusal.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Connects tried while the listener closes. Kept far below the listen backlog:
/// Windows refuses a connect once the backlog is full, so filling it would pass
/// this test without the fix.
const MAX_ATTEMPTS: usize = 20;
/// How long a completed connect is watched for the RST of a dropped listener.
const RESET_WAIT: Duration = Duration::from_secs(1);

/// Connects to `addr` until one is refused or reset, then checks the error kind.
/// A connect that completes and stays open is what a still-open listener does.
async fn assert_new_connect_refused(addr: std::net::SocketAddr) {
    let mut refused = None;
    for _ in 0..MAX_ATTEMPTS {
        match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Err(error)) => {
                refused = Some(error);
                break;
            }
            Ok(Ok(mut completed)) => {
                // A connect that races the close can complete into the backlog
                // and then get a RST when the listener drops (Linux). One that
                // stays open, unread, is what the old listener did: retry.
                let mut byte = [0u8; 1];
                if let Ok(Err(error)) =
                    tokio::time::timeout(RESET_WAIT, completed.read(&mut byte)).await
                {
                    refused = Some(error);
                    break;
                }
            }
            Err(elapsed) => panic!("a new connect hung instead of being refused: {elapsed}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let refused = refused.expect(
        "a new connect still completes after the shutdown signal: \
         the listener stayed open behind the in-flight stream",
    );
    assert!(
        matches!(
            refused.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
        ),
        "a new connect must be refused or reset, not served: {refused:?}"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_connect_is_refused_while_an_old_stream_holds_its_connection() {
    let (immutable, mutable, _execution) = test_store_create().await.expect("test stores");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
        Arc::new(lore_server::notification::local::NotificationSender::default());
    let repository_catalog = Arc::new(BaselineRepositoryCatalog::new(
        BaselineAccess::Reachable,
        immutable.clone(),
        mutable.clone(),
    ));
    let server = GrpcServerBuilder::new()
        .with_environment(EnvironmentConfig::default())
        .with_feature(FeatureSettings::default())
        .with_immutable_store(immutable.clone(), immutable)
        .with_mutable_store(mutable)
        .with_lock_store(None)
        .with_domain_context(None)
        .with_notification(notification_sender, None)
        .with_hook_dispatcher(Arc::new(HookDispatcher::empty()))
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
        .with_jwt_verifier(
            None,
            false,
            Arc::new(AllowAllRepositoryAuthorizer),
            repository_catalog,
        )
        .unwrap();
    let serving = lore_base::lore_spawn!(async move {
        server
            .serve_with_listener(listener, async {
                shutdown_rx.await.ok();
            })
            .await
    });

    let mut client = None;
    for _ in 0..100 {
        if let Ok(connected) = StorageServiceClient::connect(format!("http://{addr}")).await {
            client = Some(connected);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut client = client.expect("the test gRPC server must accept a connection");

    // A streaming Get whose request side stays open holds the connection: the
    // handler waits on the next address for as long as the sender lives.
    let (addresses, requests) = tokio::sync::mpsc::channel::<lore_proto::model::Address>(1);
    let mut request = tonic::Request::new(ReceiverStream::new(requests));
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(random::<RepositoryId>().data()),
    );
    let mut responses = client
        .get(request)
        .await
        .expect("the long stream must open")
        .into_inner();

    let _ = shutdown_tx.send(());

    assert_new_connect_refused(addr).await;
    assert!(
        !serving.is_finished(),
        "the old stream must still hold the server open, or the refusal proves nothing"
    );

    // The old connection still drains: ending the request side ends the stream
    // and lets the server finish.
    drop(addresses);
    while let Some(response) = tokio::time::timeout(CONNECT_TIMEOUT, responses.next())
        .await
        .expect("the old stream must end once its request side does")
    {
        response.expect("the old stream must end cleanly");
    }
    tokio::time::timeout(CONNECT_TIMEOUT, serving)
        .await
        .expect("the server must finish once the old stream ends")
        .expect("serving task")
        .expect("serving result");
}

/// The internal (replication and forwarded-request) server serves through the
/// same closing listener. A client-streaming `ReplicationService.Put` whose
/// request side stays open is the long stream that holds the old connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_internal_listener_refuses_a_new_connect_while_an_old_stream_holds_its_connection() {
    let (immutable, mutable, _execution) = test_store_create().await.expect("test stores");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
        Arc::new(lore_server::notification::local::NotificationSender::default());
    let server = GrpcInternalServerBuilder::new()
        .with_components(
            immutable.clone(),
            immutable,
            mutable,
            notification_sender,
            Arc::new(HookDispatcher::empty()),
            EnvironmentConfig::default(),
            None,
            None,
            Arc::new(AllowAllRepositoryAuthorizer),
        )
        .expect("the test store is local")
        .with_tls_config(None, None, None)
        .unwrap()
        .with_http2_config(None, None, Default::default(), Duration::from_secs(30))
        .unwrap();
    let serving = lore_base::lore_spawn!(async move {
        server
            .serve_with_listener(listener, async {
                shutdown_rx.await.ok();
            })
            .await
    });

    let mut client = None;
    for _ in 0..100 {
        if let Ok(connected) = ReplicationServiceClient::connect(format!("http://{addr}")).await {
            client = Some(connected);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut client = client.expect("the test internal server must accept a connection");

    // The handler reads requests for as long as the sender lives.
    let (puts, requests) = tokio::sync::mpsc::channel::<ReplicationPutRequest>(1);
    let mut responses = client
        .put(tonic::Request::new(ReceiverStream::new(requests)))
        .await
        .expect("the long stream must open")
        .into_inner();

    let _ = shutdown_tx.send(());

    assert_new_connect_refused(addr).await;
    assert!(
        !serving.is_finished(),
        "the old stream must still hold the server open, or the refusal proves nothing"
    );

    drop(puts);
    while let Some(response) = tokio::time::timeout(CONNECT_TIMEOUT, responses.next())
        .await
        .expect("the old stream must end once its request side does")
    {
        response.expect("the old stream must end cleanly");
    }
    tokio::time::timeout(CONNECT_TIMEOUT, serving)
        .await
        .expect("the server must finish once the old stream ends")
        .expect("serving task")
        .expect("serving result");
}

/// The maintenance server serves through the same closing listener. Its RPCs
/// are unary, so the old connection is held by `EnvironmentGet` sent as a
/// client stream that never delivers its one request message: the handler is
/// not called, the HTTP/2 stream stays open, and the drain cannot finish. (An
/// idle connection, or one that has sent no preface yet, does not hold the
/// server: hyper closes it at once on graceful shutdown.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_maintenance_listener_refuses_a_new_connect_while_an_old_stream_holds_its_connection() {
    let addr = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        probe.local_addr().expect("local addr")
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = lore_base::lore_spawn!(async move {
        serve_maintenance(
            EnvironmentConfig::default(),
            addr,
            None,
            None,
            None,
            async {
                shutdown_rx.await.ok();
            },
        )
        .await
    });

    let mut channel = None;
    for _ in 0..100 {
        if let Ok(connected) = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
        {
            channel = Some(connected);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let channel = channel.expect("the maintenance server must accept a connection");

    let (requests, request_stream) = tokio::sync::mpsc::channel::<EnvironmentGetRequest>(1);
    let held = lore_base::lore_spawn!(async move {
        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await.expect("channel ready");
        grpc.client_streaming::<_, EnvironmentGetRequest, EnvironmentGetResponse, _>(
            tonic::Request::new(ReceiverStream::new(request_stream)),
            http::uri::PathAndQuery::from_static(
                "/lore.environment.v1.EnvironmentService/EnvironmentGet",
            ),
            tonic_prost::ProstCodec::default(),
        )
        .await
    });
    // The request headers must reach the server before the signal; there is
    // nothing to observe on the server side, so give them time.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(());

    assert_new_connect_refused(addr).await;
    assert!(
        !serving.is_finished(),
        "the open stream must still hold the server open, or the refusal proves nothing"
    );

    // Ending the request side without a message fails that one call and lets
    // the connection, then the server, finish.
    drop(requests);
    tokio::time::timeout(CONNECT_TIMEOUT, held)
        .await
        .expect("the old call must end once its request side does")
        .expect("held task")
        .expect_err("a call without a request message must fail");
    tokio::time::timeout(CONNECT_TIMEOUT, serving)
        .await
        .expect("the server must finish once the old stream ends")
        .expect("serving task")
        .expect("serving result");
}
