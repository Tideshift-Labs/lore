// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] A fragment Put inside a managed parent writes no journal child, so a lost answer to
//! one never holds the repository fence. The real `StorageService` client runs against a local
//! tonic server that reads the Put and then loses its answer, with a durable
//! `RepositoryAttemptStore` and the real `RepositoryMutationGuard`.
#![allow(clippy::disallowed_methods)] // Only this suite's temp directories and fixture server.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_base::types::RepositoryId;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as Service;
use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::storage_client::GrpcSessionContext;
use lore_transport::grpc::storage_client::StorageService;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use uuid::Uuid;

type Responses<T> = Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;

fn unused<T>() -> Result<T, Status> {
    Err(Status::unimplemented("unused"))
}

/// Reads each Put, counts it, and loses the answer.
struct LossyStorage {
    puts: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl Service for LossyStorage {
    type PutStream = Responses<storage_v1::PutResponse>;
    async fn put(
        &self,
        request: Request<Streaming<storage_v1::PutRequest>>,
    ) -> Result<Response<Self::PutStream>, Status> {
        let mut requests = request.into_inner();
        let puts = self.puts.clone();
        Ok(Response::new(Box::pin(async_stream::stream! {
            if let Some(Ok(_item)) = requests.next().await {
                puts.fetch_add(1, Ordering::SeqCst);
                yield Err(Status::unavailable("response lost"));
            }
        })))
    }
    type GetStream = Responses<storage_v1::GetResponse>;
    async fn get(
        &self,
        _: Request<Streaming<model_v1::Address>>,
    ) -> Result<Response<Self::GetStream>, Status> {
        unused()
    }
    type GetMetadataStream = Responses<storage_v1::GetResponse>;
    async fn get_metadata(
        &self,
        _: Request<Streaming<model_v1::Address>>,
    ) -> Result<Response<Self::GetMetadataStream>, Status> {
        unused()
    }
    type GetResolvedStream = Responses<storage_v1::GetResolvedResponse>;
    async fn get_resolved(
        &self,
        _: Request<Streaming<storage_v1::GetResolvedRequest>>,
    ) -> Result<Response<Self::GetResolvedStream>, Status> {
        unused()
    }
    type PutResolvedStream = Responses<storage_v1::PutResolvedResponse>;
    async fn put_resolved(
        &self,
        _: Request<Streaming<storage_v1::PutResolvedRequest>>,
    ) -> Result<Response<Self::PutResolvedStream>, Status> {
        unused()
    }
    type CopyStream = Responses<storage_v1::CopyResponse>;
    async fn copy(
        &self,
        _: Request<Streaming<storage_v1::CopyRequest>>,
    ) -> Result<Response<Self::CopyStream>, Status> {
        unused()
    }
    async fn query(
        &self,
        _: Request<storage_v1::QueryRequest>,
    ) -> Result<Response<storage_v1::QueryResponse>, Status> {
        unused()
    }
    async fn verify(
        &self,
        _: Request<storage_v1::VerifyRequest>,
    ) -> Result<Response<storage_v1::VerifyResponse>, Status> {
        unused()
    }
    async fn mutable_load(
        &self,
        _: Request<storage_v1::MutableLoadRequest>,
    ) -> Result<Response<storage_v1::MutableLoadResponse>, Status> {
        unused()
    }
    async fn mutable_store(
        &self,
        _: Request<storage_v1::MutableStoreRequest>,
    ) -> Result<Response<storage_v1::MutableStoreResponse>, Status> {
        unused()
    }
    async fn mutable_compare_and_swap(
        &self,
        _: Request<storage_v1::MutableCompareAndSwapRequest>,
    ) -> Result<Response<storage_v1::MutableCompareAndSwapResponse>, Status> {
        unused()
    }
}

struct Fixture {
    service: StorageService,
    puts: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let puts = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let storage = LossyStorage { puts: puts.clone() };
        let server = lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(StorageServiceServer::new(storage))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Channel::from_shared(url.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let channel = tower::ServiceBuilder::new()
            .layer(lore_transport::grpc::RequestLoggerLayer {})
            .service(channel);
        let connection = Arc::new(lore_transport::grpc::GRPCConnection::for_test(
            url.parse().unwrap(),
            channel,
        ));
        Self {
            service: StorageService::new(connection),
            puts,
            server,
        }
    }

    async fn put(&self, tag: u8) -> Result<(), ProtocolError> {
        let ctx = GrpcSessionContext {
            partition: Partition::from(Context::from([0x11; 16])),
            correlation_id: "put-fence".into(),
            auth_token: String::new(),
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            self.service.put(
                0,
                &ctx,
                Address::zero_context_hash(Hash::from([tag; 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            ),
        )
        .await
        .expect("bounded put")
    }
}

fn worktree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".lore")).unwrap();
    dir
}

/// A lost Put answer leaves `unresolved()` empty, so the parent finishes and the next mutation
/// is admitted. Before the change it left an unresolved child no receipt could ever settle.
#[tokio::test]
async fn a_lost_put_answer_leaves_no_blocker_and_the_fence_reopens() {
    let f = Fixture::new().await;
    let dir = worktree();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let parent = Uuid::now_v7();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let operation = CallerOperationContext::new(
        parent,
        RepositoryId::from([0x11; 16]),
        store.clone() as Arc<dyn AttemptStore>,
    );

    // Two Puts, both losing their answer: neither is replayed, neither is recorded.
    for tag in [1, 2] {
        let error = with_caller_operation(operation.clone(), f.put(tag))
            .await
            .unwrap_err();
        assert!(!error.is_outcome_unknown(), "{error:?}");
        assert!(!error.is_disconnected(), "{error:?}");
        assert!(error.to_string().contains("lost its answer"), "{error}");
    }
    assert_eq!(f.puts.load(Ordering::SeqCst), 2, "one wire request per Put");

    assert!(store.unresolved().await.unwrap().is_empty());
    store.complete_parent_body(parent).await.unwrap();
    guard.finish(parent).await.unwrap();
    assert!(store.managed_parents().await.unwrap()[0].complete);
    drop(store);
    drop(guard);

    RepositoryMutationGuard::acquire(dir.path())
        .await
        .expect("a lost Put answer must not hold the repository fence");
}
