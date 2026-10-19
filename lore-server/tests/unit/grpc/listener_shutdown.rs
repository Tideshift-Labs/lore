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

use lore_revision::environment::EnvironmentConfig;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
use lore_server::grpc::server::FeatureSettings;
use lore_server::grpc::server::GrpcServerBuilder;
use lore_server::grpc::server::GrpcTimeouts;
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
