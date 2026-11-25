// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-120): a `BranchPush` against a real tonic server, on the managed
//! (journalled) path and on the unmanaged classified path.
//!
//! A lost answer is `BranchPushError::OutcomeUnknown` on both and is never sent again; the managed
//! record stays unresolved. The remote's marked refusal of a push onto a moved latest stays
//! `BranchAdvanced` on the managed path and settles the record not applied; it is not flattened
//! into `Internal` by the `ProtocolError` the journal speaks.
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_base::types::BranchId;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_proto::lore::revision::v1 as revision_v1;
use lore_proto::lore::revision::v1::revision_service_server::RevisionService as Server;
use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
use lore_proto::lore::revision::v1::*;
use lore_transport::BranchPushError;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::GRPCConnection;
use lore_transport::grpc::RequestLoggerLayer;
use lore_transport::grpc::branch_advanced_status;
use lore_transport::grpc::revision_client::RevisionService;
use lore_transport::grpc::with_reconnect_classified;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;
use lore_transport::types::BranchPushResponse;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tower::ServiceBuilder;
use uuid::Uuid;

// Only syntax is tested here; this disposable server does not verify JWT signatures.
const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

/// A volatile journal that accepts the managed intent and remembers which attempts it saw.
#[derive(Default)]
struct Journal {
    inner: VolatileAttemptStore,
    recorded: parking_lot::Mutex<Vec<AttemptId>>,
}

#[async_trait::async_trait]
impl AttemptStore for Journal {
    async fn record_managed(
        &self,
        record: &AttemptRecord,
        _intent: &ManagedAttemptIntent,
    ) -> Result<(), ProtocolError> {
        self.recorded.lock().push(record.attempt_id);
        self.inner.record(record).await
    }
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        self.inner.record(record).await
    }
    async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        self.inner.lookup(id).await
    }
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        self.inner.unresolved().await
    }
    async fn resolve(
        &self,
        id: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        self.inner.resolve(id, resolution).await
    }
    async fn record_ownership(&self, _: &LockOwnership) -> Result<(), ProtocolError> {
        unreachable!()
    }
    async fn ownership_for(
        &self,
        _: &Context,
        _: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        unreachable!()
    }
    async fn clear_ownership(&self, _: &Context, _: &Hash) -> Result<(), ProtocolError> {
        unreachable!()
    }
}

/// Answers every `BranchPush` with one scripted status, counting the pushes that reached it.
struct PushServer {
    status: Status,
    pushes: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl Server for PushServer {
    async fn branch_push(
        &self,
        _: Request<BranchPushRequest>,
    ) -> Result<Response<revision_v1::BranchPushResponse>, Status> {
        self.pushes.fetch_add(1, Ordering::SeqCst);
        Err(self.status.clone())
    }
    async fn branch_create(
        &self,
        _: Request<BranchCreateRequest>,
    ) -> Result<Response<BranchCreateResponse>, Status> {
        panic!("unexpected create")
    }
    async fn branch_delete(
        &self,
        _: Request<BranchDeleteRequest>,
    ) -> Result<Response<BranchDeleteResponse>, Status> {
        panic!("unexpected delete")
    }
    async fn branch_get(
        &self,
        _: Request<BranchGetRequest>,
    ) -> Result<Response<BranchGetResponse>, Status> {
        panic!("unexpected get")
    }
    type BranchListStream = tokio_stream::Empty<Result<revision_v1::BranchListResponse, Status>>;
    async fn branch_list(
        &self,
        _: Request<BranchListRequest>,
    ) -> Result<Response<Self::BranchListStream>, Status> {
        panic!("unexpected list")
    }
    async fn branch_metadata_get(
        &self,
        _: Request<BranchMetadataGetRequest>,
    ) -> Result<Response<BranchMetadataGetResponse>, Status> {
        panic!("unexpected metadata get")
    }
    async fn branch_metadata_set(
        &self,
        _: Request<BranchMetadataSetRequest>,
    ) -> Result<Response<BranchMetadataSetResponse>, Status> {
        panic!("unexpected metadata set")
    }
    async fn revision_list(
        &self,
        _: Request<RevisionListRequest>,
    ) -> Result<Response<revision_v1::RevisionListResponse>, Status> {
        panic!("unexpected revision list")
    }
}

struct Fixture {
    client: RevisionService,
    journal: Arc<Journal>,
    pushes: Arc<AtomicUsize>,
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn outcome_unknown_marked(mut status: Status) -> Status {
    status.metadata_mut().insert(
        lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
        lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_VALUE
            .parse()
            .unwrap(),
    );
    status
}

fn moved_latest() -> Status {
    branch_advanced_status(Hash::from([0x44; 32]), "Branch push is not a fast-forward")
}

impl Fixture {
    async fn new(status: Status) -> Self {
        let pushes = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let service = PushServer {
            status,
            pushes: pushes.clone(),
        };
        let task = lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(RevisionServiceServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Channel::from_shared(endpoint.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let channel = ServiceBuilder::new()
            .layer(RequestLoggerLayer {})
            .service(channel);
        let auth = Arc::new(parking_lot::RwLock::new(lore_transport::grpc::GRPCAuth {
            authentication_token: TOKEN.into(),
            authorization_token: TOKEN.into(),
            ..Default::default()
        }));
        Self {
            client: RevisionService::new(channel, RepositoryId::from([0x11; 16]), auth),
            journal: Arc::new(Journal::default()),
            pushes,
            endpoint,
            task,
        }
    }

    async fn push(&self) -> Result<BranchPushResponse, BranchPushError> {
        self.client
            .branch_push(
                BranchId::from([0x22; 16]),
                Hash::from([0x33; 32]),
                false,
                false,
            )
            .await
    }

    /// One managed (journalled) branch push.
    async fn managed_push(&self) -> Result<BranchPushResponse, BranchPushError> {
        let context = CallerOperationContext::new(
            Uuid::now_v7(),
            RepositoryId::from([0x11; 16]),
            self.journal.clone(),
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            with_caller_operation(
                context,
                lore_transport::caller_operation::with_transport_endpoint(
                    self.endpoint.clone(),
                    self.push(),
                ),
            ),
        )
        .await
        .expect("bounded branch push")
    }

    /// The one attempt the managed push journalled, and its state.
    async fn the_attempt(&self) -> AttemptState {
        let recorded = self.journal.recorded.lock().clone();
        assert_eq!(recorded.len(), 1, "one dispatch, one record");
        self.journal
            .lookup(&recorded[0])
            .await
            .unwrap()
            .expect("the attempt must be journalled")
            .state
    }

    fn pushes(&self) -> usize {
        self.pushes.load(Ordering::SeqCst)
    }
}

/// A connection that reaches nothing; `with_reconnect_classified` never dials on a mutation.
fn dummy_connection() -> GRPCConnection {
    let endpoint = tonic::transport::Endpoint::from_shared("http://127.0.0.1:1".to_string())
        .expect("test endpoint");
    let channel = ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(endpoint.connect_lazy());
    GRPCConnection::for_test("http://127.0.0.1:1".parse().expect("test url"), channel)
}

/// Managed: a push whose answer is lost fails `OutcomeUnknown`, the server saw it once, and the
/// attempt stays unresolved. Both shapes of a lost answer: a dropped channel and a cancelled call.
#[tokio::test]
async fn a_managed_push_with_a_lost_answer_is_outcome_unknown_and_stays_unresolved() {
    for lost in [
        Status::unavailable("response unavailable after dispatch"),
        Status::cancelled("mid-flight stream reset"),
    ] {
        let rendered = lost.to_string();
        let f = Fixture::new(lost).await;

        let error = f
            .managed_push()
            .await
            .err()
            .expect("a lost answer is an error");

        assert!(
            matches!(error, BranchPushError::OutcomeUnknown(_)),
            "{rendered}: {error:?}"
        );
        assert_eq!(f.pushes(), 1, "{rendered}: never sent again");
        assert_eq!(
            f.the_attempt().await,
            AttemptState::Unresolved,
            "{rendered}"
        );
        assert_eq!(f.journal.unresolved().await.unwrap().len(), 1, "{rendered}");
    }
}

/// Managed: the remote's marked refusal of a push onto a moved latest is `BranchAdvanced`, not
/// `Internal`, and the attempt settles not applied.
#[tokio::test]
async fn a_managed_marked_refusal_stays_branch_advanced_and_settles_not_applied() {
    let f = Fixture::new(moved_latest()).await;

    let error = f.managed_push().await.err().expect("a refusal is an error");

    assert!(
        matches!(error, BranchPushError::BranchAdvanced(_)),
        "{error:?}"
    );
    assert!(
        !error.is_internal() && !error.is_outcome_unknown(),
        "{error:?}"
    );
    assert_eq!(f.pushes(), 1);
    assert_eq!(
        f.the_attempt().await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

/// Managed: a status with the refusal's details that ALSO marks its outcome unknown is the unknown
/// outcome: the push may have applied, so the record stays open.
#[tokio::test]
async fn a_managed_refusal_marked_outcome_unknown_stays_unresolved() {
    let f = Fixture::new(outcome_unknown_marked(moved_latest())).await;

    let error = f
        .managed_push()
        .await
        .err()
        .expect("an unknown outcome is an error");

    assert!(
        matches!(error, BranchPushError::OutcomeUnknown(_)),
        "{error:?}"
    );
    assert_eq!(f.the_attempt().await, AttemptState::Unresolved);
}

/// Managed negative control: any other server refusal keeps its own variant and settles not
/// applied; the split must not turn every refusal into a maybe.
#[tokio::test]
async fn a_managed_plain_refusal_stays_decisive() {
    let f = Fixture::new(Status::permission_denied("protected branch")).await;

    let error = f.managed_push().await.err().expect("a refusal is an error");

    assert!(
        matches!(error, BranchPushError::NotAuthorized(_)),
        "{error:?}"
    );
    assert_eq!(
        f.the_attempt().await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
}

/// FORK-LOCAL (Tideshift, CR-019): the managed push answers the server's marked lock refusal as
/// `LockNotOwned`, not `NotAuthorized`; the answer is decisive and the attempt settles not applied.
#[tokio::test]
async fn a_managed_lock_refusal_stays_lock_not_owned_and_settles_not_applied() {
    let f = Fixture::new(lore_transport::grpc::push_lock_refused_status(
        "push blocked: 1 file(s) changed are locked by another user: 'a.bin' is locked by alice",
    ))
    .await;

    let error = f.managed_push().await.err().expect("a refusal is an error");

    assert!(
        matches!(error, BranchPushError::LockNotOwned(_)),
        "{error:?}"
    );
    assert!(
        !error.is_outcome_unknown() && !matches!(error, BranchPushError::NotAuthorized(_)),
        "{error:?}"
    );
    assert_eq!(f.pushes(), 1, "a refusal is never sent again");
    assert_eq!(
        f.the_attempt().await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

/// Unmanaged classified path: a lost answer is `OutcomeUnknown`, the call is sent once and the
/// channel is never rebuilt for a replay.
#[tokio::test]
async fn an_unmanaged_push_with_a_lost_answer_is_outcome_unknown_and_not_resent() {
    for lost in [
        Status::unavailable("response unavailable after dispatch"),
        Status::cancelled("mid-flight stream reset"),
        Status::deadline_exceeded("grpc-timeout expired"),
    ] {
        let rendered = lost.to_string();
        let f = Fixture::new(lost).await;
        let connection = dummy_connection();
        let rebuilds = AtomicUsize::new(0);

        let result: Result<BranchPushResponse, BranchPushError> = with_reconnect_classified(
            &connection,
            GrpcRpc::RevisionBranchPush,
            || f.push(),
            |_| async {
                rebuilds.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        let error = result.err().expect("a lost answer is an error");
        assert!(
            matches!(error, BranchPushError::OutcomeUnknown(_)),
            "{rendered}: {error:?}"
        );
        assert_eq!(f.pushes(), 1, "{rendered}: never sent again");
        assert_eq!(
            rebuilds.load(Ordering::SeqCst),
            0,
            "{rendered}: no reconnect replay"
        );
    }
}

/// Unmanaged negative control: the marked refusal stays `BranchAdvanced` through the classifier.
#[tokio::test]
async fn an_unmanaged_marked_refusal_stays_branch_advanced() {
    let f = Fixture::new(moved_latest()).await;
    let connection = dummy_connection();

    let result: Result<BranchPushResponse, BranchPushError> = with_reconnect_classified(
        &connection,
        GrpcRpc::RevisionBranchPush,
        || f.push(),
        |_| async { Ok(()) },
    )
    .await;

    let error = result.err().expect("a refusal is an error");
    assert!(
        matches!(error, BranchPushError::BranchAdvanced(_)),
        "{error:?}"
    );
    assert_eq!(f.pushes(), 1);
}
