// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124: `GRPCStorage::session_start_declared` is byte-identical to `session_start` on the wire.
//!
//! [CLIENT]-class (`lore-transport`). gRPC declares per request, so a declared session needs
//! nothing an undeclared one lacks; the trait method only changed its return type to carry the
//! connection generation, which for gRPC is the constant its sessions always report. Two storages
//! built alike against one recording server run the same workflow, one started with
//! `session_start` and one with `session_start_declared`. The server records every RPC's path,
//! full metadata and body; the two recordings must be equal, and the start itself must send
//! nothing.
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use dashmap::DashMap;
use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
use lore_transport::Storage;
use lore_transport::grpc::GRPCConnection;
use lore_transport::grpc::GRPCStorage;
use lore_transport::grpc::RequestLoggerLayer;
use lore_transport::grpc::storage_client::StorageService;
use prost::Message;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use tonic::metadata::KeyAndValueRef;
use tonic::metadata::MetadataMap;

/// One RPC as the server saw it: which one, every header, and the request message.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Captured {
    rpc: &'static str,
    metadata: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Every header, sorted, binary values hex-encoded. Nothing is filtered out: a header the
/// declared path added would show as a difference.
fn dump(metadata: &MetadataMap) -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = metadata
        .iter()
        .map(|entry| match entry {
            KeyAndValueRef::Ascii(key, value) => (
                key.as_str().to_string(),
                value.to_str().unwrap_or("<non-ascii>").to_string(),
            ),
            KeyAndValueRef::Binary(key, value) => (
                key.as_str().to_string(),
                value
                    .to_bytes()
                    .map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect())
                    .unwrap_or_default(),
            ),
        })
        .collect();
    all.sort();
    all
}

type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// Records `Query` and `Put`; every other RPC is unreachable from this test.
struct RecordingStorageServer {
    seen: Arc<Mutex<Vec<Captured>>>,
}

#[tonic::async_trait]
impl StorageServiceV1 for RecordingStorageServer {
    async fn query(
        &self,
        request: Request<storage_v1::QueryRequest>,
    ) -> Result<Response<storage_v1::QueryResponse>, Status> {
        self.seen.lock().expect("seen mutex").push(Captured {
            rpc: "query",
            metadata: dump(request.metadata()),
            body: request.get_ref().encode_to_vec(),
        });
        Ok(Response::new(storage_v1::QueryResponse {
            results: vec![1],
        }))
    }

    type PutStream = ResponseStream<storage_v1::PutResponse>;

    async fn put(
        &self,
        request: Request<Streaming<storage_v1::PutRequest>>,
    ) -> Result<Response<Self::PutStream>, Status> {
        let metadata = dump(request.metadata());
        let seen = self.seen.clone();
        let mut requests = request.into_inner();
        let stream = async_stream::stream! {
            while let Some(Ok(req)) = requests.next().await {
                seen.lock().expect("seen mutex").push(Captured {
                    rpc: "put",
                    metadata: metadata.clone(),
                    body: req.encode_to_vec(),
                });
                yield Ok(storage_v1::PutResponse {
                    address: req.address,
                    status: None,
                });
            }
        };
        Ok(Response::new(Box::pin(stream) as Self::PutStream))
    }

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

    type CopyStream = ResponseStream<storage_v1::CopyResponse>;

    async fn copy(
        &self,
        _request: Request<Streaming<storage_v1::CopyRequest>>,
    ) -> Result<Response<Self::CopyStream>, Status> {
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

async fn start_server() -> (SocketAddr, Arc<Mutex<Vec<Captured>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server = RecordingStorageServer { seen: seen.clone() };
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(StorageServiceServer::new(server))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });
    (addr, seen)
}

/// A storage over its own connection to `addr`, built the way the other `GRPCStorage` tests do.
async fn storage(addr: SocketAddr) -> GRPCStorage {
    let url = format!("http://{addr}");
    let channel = tonic::transport::Channel::from_shared(url.clone())
        .expect("url")
        .connect()
        .await
        .expect("connect to the recording server");
    let channel = tower::ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(channel);
    let connection = Arc::new(GRPCConnection::for_test(
        url.parse().expect("test url"),
        channel,
    ));
    GRPCStorage {
        connection: connection.clone(),
        client: StorageService::new(connection),
        auth_url: String::new(),
        identity: String::new(),
        credentials: Arc::new(lore_transport::connection::SuppliedCredentials::default()),
        session_counter: std::sync::atomic::AtomicU32::new(1),
        sessions: DashMap::new(),
    }
}

fn partition() -> Partition {
    Partition::from([0x31u8; 16])
}

fn address() -> Address {
    Address::zero_context_hash(Hash::from([0x42u8; 32]))
}

/// The workflow both storages run on their session: a unary read and a streamed write.
async fn run(storage: &GRPCStorage, session: u32) {
    storage
        .query(session, &[address()])
        .await
        .expect("query on the session");
    let payload = Bytes::from_static(b"wp124 byte identity");
    storage
        .put(
            session,
            address(),
            Fragment {
                flags: 0,
                size_payload: payload.len() as u32,
                size_content: payload.len() as u64,
            },
            Some(payload),
        )
        .await
        .expect("put on the session");
}

#[tokio::test]
async fn grpc_session_start_declared_sends_exactly_what_session_start_sends() {
    let (addr, seen) = start_server().await;

    let plain = storage(addr).await;
    let plain_session = plain
        .session_start(partition(), "byte-identity")
        .await
        .expect("session_start");
    assert!(
        seen.lock().expect("seen mutex").is_empty(),
        "an undeclared gRPC start is local: it sends nothing"
    );
    run(&plain, plain_session).await;
    let after_plain = seen.lock().expect("seen mutex").len();
    assert_eq!(after_plain, 2, "one query and one put");

    let declared = storage(addr).await;
    let (declared_session, generation) = declared
        .session_start_declared(partition(), "byte-identity", "outcome_unknown_v1")
        .await
        .expect("session_start_declared");
    assert_eq!(
        seen.lock().expect("seen mutex").len(),
        after_plain,
        "a declared gRPC start sends nothing either"
    );
    run(&declared, declared_session).await;

    let all = seen.lock().expect("seen mutex").clone();
    assert_eq!(all.len(), 4, "{all:?}");
    let (first, second) = all.split_at(2);
    assert_eq!(
        first, second,
        "the declared start's session sends the same RPCs, metadata and bodies"
    );
    // Positive control: the comparison above is over real content, not two empty recordings.
    assert!(
        first.iter().all(|call| !call.metadata.is_empty()),
        "the session metadata (partition, repository, correlation) is on every RPC: {first:?}"
    );
    assert_eq!(first[0].rpc, "query");
    assert_eq!(first[1].rpc, "put");
    assert!(!first[0].body.is_empty() && !first[1].body.is_empty());

    assert_eq!(
        declared_session, plain_session,
        "the same counter, the same id"
    );
    assert_eq!(
        generation,
        declared.connection_generation(),
        "gRPC reports its static session generation"
    );
    assert_eq!(generation, plain.connection_generation());
}

/// `session_start_bound`'s default on a transport whose generation never moves.
#[tokio::test]
async fn grpc_session_start_bound_returns_the_static_generation() {
    let (addr, seen) = start_server().await;
    let storage = storage(addr).await;
    let (session, generation) = storage
        .session_start_bound(partition(), "bound")
        .await
        .expect("session_start_bound");
    assert_eq!(generation, storage.connection_generation());
    assert!(seen.lock().expect("seen mutex").is_empty());
    storage
        .query(session, &[address()])
        .await
        .expect("the session is usable");
}
