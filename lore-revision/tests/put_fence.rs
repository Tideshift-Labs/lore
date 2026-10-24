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

/// Reads each Put, Copy and `PutResolved`, counts it, and loses the answer. A Copy is instead
/// refused decisively, with a correlated per-item status, when `copy_refusal` is set.
struct LossyStorage {
    puts: Arc<AtomicUsize>,
    copies: Arc<AtomicUsize>,
    resolved: Arc<AtomicUsize>,
    copy_refusal: bool,
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
        request: Request<Streaming<storage_v1::PutResolvedRequest>>,
    ) -> Result<Response<Self::PutResolvedStream>, Status> {
        let mut requests = request.into_inner();
        let resolved = self.resolved.clone();
        Ok(Response::new(Box::pin(async_stream::stream! {
            if let Some(Ok(_item)) = requests.next().await {
                resolved.fetch_add(1, Ordering::SeqCst);
                yield Err(Status::unavailable("response lost"));
            }
        })))
    }
    type CopyStream = Responses<storage_v1::CopyResponse>;
    async fn copy(
        &self,
        request: Request<Streaming<storage_v1::CopyRequest>>,
    ) -> Result<Response<Self::CopyStream>, Status> {
        let mut requests = request.into_inner();
        let copies = self.copies.clone();
        let refuse = self.copy_refusal;
        Ok(Response::new(Box::pin(async_stream::stream! {
            if let Some(Ok(item)) = requests.next().await {
                copies.fetch_add(1, Ordering::SeqCst);
                if refuse {
                    // A decisive, correlated per-item refusal: the source is not held.
                    yield Ok(storage_v1::CopyResponse {
                        source_repository_id: item.source_repository_id.clone(),
                        source_address: item.source_address.clone(),
                        status: Some(model_v1::ItemStatus {
                            code: 1,
                            message: "decisive per-item refusal".into(),
                            ..Default::default()
                        }),
                    });
                } else {
                    yield Err(Status::unavailable("response lost"));
                }
            }
        })))
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
    copies: Arc<AtomicUsize>,
    resolved: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::build(false).await
    }

    /// A peer that refuses every Copy decisively instead of losing its answer.
    async fn refusing_copy() -> Self {
        Self::build(true).await
    }

    async fn build(copy_refusal: bool) -> Self {
        let puts = Arc::new(AtomicUsize::new(0));
        let copies = Arc::new(AtomicUsize::new(0));
        let resolved = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let storage = LossyStorage {
            puts: puts.clone(),
            copies: copies.clone(),
            resolved: resolved.clone(),
            copy_refusal,
        };
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
            copies,
            resolved,
            server,
        }
    }

    #[allow(clippy::unused_self)] // Reads as a method of the fixture beside its siblings.
    fn context(&self) -> GrpcSessionContext {
        GrpcSessionContext {
            partition: Partition::from(Context::from([0x11; 16])),
            correlation_id: "put-fence".into(),
            auth_token: String::new(),
        }
    }

    async fn copy(&self, tag: u8) -> Result<(), ProtocolError> {
        let ctx = self.context();
        tokio::time::timeout(
            Duration::from_secs(5),
            self.service.copy(
                0,
                &ctx,
                ctx.partition,
                Address::zero_context_hash(Hash::from([tag; 32])),
                Context::from([0x12; 16]),
            ),
        )
        .await
        .expect("bounded copy")
    }

    async fn put_resolved(&self, tag: u8) -> Result<(), ProtocolError> {
        let ctx = self.context();
        tokio::time::timeout(
            Duration::from_secs(5),
            self.service.put_resolved(
                0,
                &ctx,
                &Hash::from([tag; 32]),
                Address::zero_context_hash(Hash::from([tag.wrapping_add(1); 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            ),
        )
        .await
        .expect("bounded put_resolved")
    }

    async fn put(&self, tag: u8) -> Result<(), ProtocolError> {
        let ctx = self.context();
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

/// A managed parent with a durable journal and the real fence.
struct Managed {
    dir: tempfile::TempDir,
    guard: RepositoryMutationGuard,
    store: Arc<lore_revision::attempt_store::RepositoryAttemptStore>,
    parent: Uuid,
    operation: CallerOperationContext,
}

async fn managed() -> Managed {
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
    Managed {
        dir,
        guard,
        store,
        parent,
        operation,
    }
}

impl Managed {
    /// The parent completes and the next write is admitted: nothing holds the fence.
    async fn assert_fence_reopens(self) {
        assert!(self.store.unresolved().await.unwrap().is_empty());
        self.store.complete_parent_body(self.parent).await.unwrap();
        self.guard.finish(self.parent).await.unwrap();
        assert!(self.store.managed_parents().await.unwrap()[0].complete);
        let dir = self.dir;
        drop(self.store);
        drop(self.guard);
        RepositoryMutationGuard::acquire(dir.path())
            .await
            .expect("a lost managed answer must not hold the repository fence");
    }
}

/// What `duplicate_association` does with a failed Copy: upload the payload with a Put only when
/// `copy_failure_allows_upload`. The real push path needs a resolved `StorageSession`, which no
/// public constructor builds over a local server, so this drives the same service call and the
/// same predicate it uses.
async fn copy_then_fall_back(f: &Fixture, operation: &CallerOperationContext, tag: u8) -> bool {
    let error = with_caller_operation(operation.clone(), f.copy(tag))
        .await
        .unwrap_err();
    if !lore_revision::branch::push::copy_failure_allows_upload(&error) {
        return false;
    }
    let _ = with_caller_operation(operation.clone(), f.put(tag)).await;
    true
}

/// A lost managed Copy answer fails retryably, is not an unknown outcome, is sent once, writes no
/// child, and the push may not fall back to a Put for that address.
#[tokio::test]
async fn a_lost_copy_answer_fails_the_push_without_a_fallback_put_and_the_fence_reopens() {
    let f = Fixture::new().await;
    let m = managed().await;

    let error = with_caller_operation(m.operation.clone(), f.copy(3))
        .await
        .unwrap_err();
    assert!(matches!(error, ProtocolError::Internal(_)), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(!error.is_disconnected(), "{error:?}");
    assert!(
        lore_transport::is_unjournaled_answer_lost(&error),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("StorageService.Copy")
            && error.to_string().contains("lost its answer"),
        "{error}"
    );
    assert_eq!(f.copies.load(Ordering::SeqCst), 1, "sent exactly once");
    assert!(!lore_revision::branch::push::copy_failure_allows_upload(
        &error
    ));

    // The push's decision: no fallback Put for that address.
    assert!(!copy_then_fall_back(&f, &m.operation, 4).await);
    assert_eq!(f.copies.load(Ordering::SeqCst), 2);
    assert_eq!(f.puts.load(Ordering::SeqCst), 0, "no fallback Put was sent");

    m.assert_fence_reopens().await;
}

/// A decisive Copy refusal still falls back to uploading the payload.
#[tokio::test]
async fn a_decisive_copy_refusal_still_falls_back_to_a_put_and_the_fence_reopens() {
    let f = Fixture::refusing_copy().await;
    let m = managed().await;

    let error = with_caller_operation(m.operation.clone(), f.copy(5))
        .await
        .unwrap_err();
    assert!(
        !lore_transport::is_unjournaled_answer_lost(&error),
        "{error:?}"
    );
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(lore_revision::branch::push::copy_failure_allows_upload(
        &error
    ));

    assert!(copy_then_fall_back(&f, &m.operation, 6).await);
    assert_eq!(f.copies.load(Ordering::SeqCst), 2);
    assert_eq!(
        f.puts.load(Ordering::SeqCst),
        1,
        "the fallback Put was sent"
    );

    m.assert_fence_reopens().await;
}

/// A lost managed `PutResolved` answer fails its caller retryably, is sent once, and leaves no
/// journal child and no fence block.
#[tokio::test]
async fn a_lost_put_resolved_answer_leaves_no_blocker_and_the_fence_reopens() {
    let f = Fixture::new().await;
    let m = managed().await;

    for tag in [7, 8] {
        let error = with_caller_operation(m.operation.clone(), f.put_resolved(tag))
            .await
            .unwrap_err();
        assert!(matches!(error, ProtocolError::Internal(_)), "{error:?}");
        assert!(!error.is_outcome_unknown(), "{error:?}");
        assert!(!error.is_disconnected(), "{error:?}");
        assert!(
            lore_transport::is_unjournaled_answer_lost(&error),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("StorageService.PutResolved")
                && error.to_string().contains("lost its answer"),
            "{error}"
        );
    }
    assert_eq!(
        f.resolved.load(Ordering::SeqCst),
        2,
        "one wire request each"
    );

    m.assert_fence_reopens().await;
}
