// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Client dispatch proof against a real tonic server; the journal double is not disk proof.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use lore_base::types::BranchId;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::revision::v1 as revision_v1;
use lore_proto::lore::revision::v1::revision_service_server::RevisionService as Server;
use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
use lore_proto::lore::revision::v1::*;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::revision_client::RevisionService;
use lore_transport::outcome::AttemptId;
use lore_transport::types::BranchRecord;
use prost::Message;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use uuid::Uuid;

// Only syntax is tested here; this disposable server does not verify JWT signatures.
const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

#[derive(Default)]
struct Journal {
    inner: VolatileAttemptStore,
    intents: parking_lot::Mutex<Vec<(AttemptRecord, ManagedAttemptIntent)>>,
    fail_record: AtomicBool,
    fail_settle: AtomicBool,
}

#[async_trait::async_trait]
impl AttemptStore for Journal {
    async fn record_managed(
        &self,
        record: &AttemptRecord,
        intent: &ManagedAttemptIntent,
    ) -> Result<(), ProtocolError> {
        self.record(record).await?;
        self.intents.lock().push((record.clone(), intent.clone()));
        Ok(())
    }
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        if self.fail_record.load(Ordering::SeqCst) {
            return Err(ProtocolError::internal("injected journal failure"));
        }
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
        if self.fail_settle.load(Ordering::SeqCst) {
            return Err(ProtocolError::internal("injected settlement failure"));
        }
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

#[derive(Clone, Copy)]
enum Reply {
    Success,
    Loss,
    Refusal,
    Malformed,
    ExpiredReceipt,
}

struct FixtureServer {
    journal: Arc<Journal>,
    seen: Arc<parking_lot::Mutex<Vec<BranchCreateRequest>>>,
    reply: Reply,
}

#[tonic::async_trait]
impl Server for FixtureServer {
    async fn branch_create(
        &self,
        request: Request<BranchCreateRequest>,
    ) -> Result<Response<BranchCreateResponse>, Status> {
        assert_eq!(
            request
                .metadata()
                .get("lore-caller-capabilities-v1")
                .unwrap(),
            "outcome_unknown_v1"
        );
        assert_eq!(
            request.metadata().get("lore-authn-bearer").unwrap(),
            format!("Bearer {TOKEN}").as_str()
        );
        let id = Uuid::parse_str(
            request
                .metadata()
                .get("lore-attempt-id")
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let recorded = self.journal.intents.lock();
        assert_eq!(recorded.len(), 1, "journal must precede wire dispatch");
        assert_eq!(recorded[0].0.attempt_id.to_string(), id.to_string());
        assert_eq!(recorded[0].1.rpc, "RevisionService.BranchCreate");
        assert_eq!(
            recorded[0].1.canonical_request,
            request.get_ref().encode_to_vec()
        );
        drop(recorded);
        let request = request.into_inner();
        self.seen.lock().push(request.clone());
        match self.reply {
            Reply::Success | Reply::Malformed => Ok(Response::new(BranchCreateResponse {
                branch: Some(model_v1::Branch {
                    id: request.id,
                    name: request.name,
                    creator: "fixture-user".into(),
                    latest: vec![0x35; 32].into(),
                    metadata: vec![
                        0x36;
                        if matches!(self.reply, Reply::Malformed) {
                            31
                        } else {
                            32
                        }
                    ]
                    .into(),
                    ..Default::default()
                }),
            })),
            Reply::Loss => Err(Status::unavailable("response unavailable after dispatch")),
            Reply::Refusal => Err(Status::permission_denied("write refused")),
            Reply::ExpiredReceipt => {
                let mut status = Status::aborted("terminal payload expired");
                status.metadata_mut().insert(
                    lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
                    lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_VALUE
                        .parse()
                        .unwrap(),
                );
                Err(status)
            }
        }
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
    async fn branch_push(
        &self,
        _: Request<BranchPushRequest>,
    ) -> Result<Response<revision_v1::BranchPushResponse>, Status> {
        panic!("unexpected push")
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
    seen: Arc<parking_lot::Mutex<Vec<BranchCreateRequest>>>,
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(reply: Reply) -> Self {
        let journal = Arc::new(Journal::default());
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let service = FixtureServer {
            journal: journal.clone(),
            seen: seen.clone(),
            reply,
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
        let channel = tower::ServiceBuilder::new()
            .layer(lore_transport::grpc::RequestLoggerLayer {})
            .service(channel);
        let auth = Arc::new(parking_lot::RwLock::new(lore_transport::grpc::GRPCAuth {
            authentication_token: TOKEN.into(),
            authorization_token: TOKEN.into(),
            ..Default::default()
        }));
        Self {
            client: RevisionService::new(channel, RepositoryId::from([0x11; 16]), auth),
            journal,
            seen,
            endpoint,
            task,
        }
    }
    async fn create(&self, repository: RepositoryId) -> Result<BranchRecord, ProtocolError> {
        let operation =
            CallerOperationContext::new(Uuid::now_v7(), repository, self.journal.clone());
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            with_caller_operation(
                operation,
                lore_transport::caller_operation::with_transport_endpoint(
                    self.endpoint.clone(),
                    self.client.branch_create(
                        BranchId::from([0x22; 16]),
                        "feature",
                        "category",
                        "foreign",
                        &[],
                    ),
                ),
            ),
        )
        .await
        .expect("bounded branch create")
    }
}

#[tokio::test]
async fn managed_create_records_exact_intent_before_one_dispatch() {
    let fixture = Fixture::new(Reply::Success).await;
    assert_eq!(
        fixture
            .create(RepositoryId::from([0x11; 16]))
            .await
            .unwrap()
            .latest,
        Hash::from([0x35; 32])
    );
    assert_eq!(fixture.seen.lock().len(), 1);
    let (record, intent) = fixture.journal.intents.lock()[0].clone();
    assert_eq!(intent.authenticated_subject, "fixture-user");
    assert_eq!(
        BranchCreateRequest::decode(intent.canonical_request.as_slice())
            .unwrap()
            .creator
            .as_deref(),
        Some("foreign")
    );
    assert_eq!(
        fixture
            .journal
            .lookup(&record.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        lore_transport::attempt_store::AttemptState::Resolved(AttemptResolution::Applied)
    );
}

#[tokio::test]
async fn dispatched_failure_never_enters_the_legacy_retry_loop() {
    for reply in [
        Reply::Loss,
        Reply::Refusal,
        Reply::Malformed,
        Reply::ExpiredReceipt,
    ] {
        let fixture = Fixture::new(reply).await;
        let error = fixture
            .create(RepositoryId::from([0x11; 16]))
            .await
            .unwrap_err();
        assert_eq!(fixture.seen.lock().len(), 1);
        if matches!(
            reply,
            Reply::Loss | Reply::Malformed | Reply::ExpiredReceipt
        ) {
            assert!(error.is_outcome_unknown(), "{error:?}");
            let unresolved = fixture.journal.unresolved().await.unwrap();
            assert_eq!(unresolved.len(), 1);
            let recorded = fixture.journal.intents.lock()[0].0.attempt_id;
            assert_eq!(unresolved[0].attempt_id, recorded);
            assert!(format!("{error:?}").contains(&recorded.to_string()));
        }
    }
}

#[tokio::test]
async fn failed_pre_dispatch_journaling_or_repository_mismatch_sends_nothing() {
    for wrong_repository in [false, true] {
        let fixture = Fixture::new(Reply::Success).await;
        fixture
            .journal
            .fail_record
            .store(!wrong_repository, Ordering::SeqCst);
        let repository = RepositoryId::from([if wrong_repository { 0x99 } else { 0x11 }; 16]);
        assert!(fixture.create(repository).await.is_err());
        assert!(fixture.seen.lock().is_empty());
        assert!(fixture.journal.intents.lock().is_empty());
    }
}

#[tokio::test]
async fn successful_wire_reply_cannot_hide_failed_journal_settlement() {
    let fixture = Fixture::new(Reply::Success).await;
    fixture.journal.fail_settle.store(true, Ordering::SeqCst);
    assert!(
        fixture
            .create(RepositoryId::from([0x11; 16]))
            .await
            .is_err()
    );
    assert_eq!(fixture.seen.lock().len(), 1);
    assert_eq!(fixture.journal.unresolved().await.unwrap().len(), 1);
}

/// Upstream v0.13 `collect_branch_list` bounds, kept in their own module so their imports do not
/// collide with the managed-journal fixture above.
mod branch_list_collection {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use lore_proto::lore::model::v1 as model;
    use lore_proto::lore::revision::v1 as proto;
    use lore_transport::grpc::revision_client::collect_branch_list;
    use tokio_stream::StreamExt;

    fn branch(index: usize) -> Result<proto::BranchListResponse, tonic::Status> {
        Ok(proto::BranchListResponse {
            branch: Some(model::Branch {
                name: index.to_string(),
                ..Default::default()
            }),
        })
    }

    #[tokio::test]
    async fn exact_limit_preserves_all_branches() {
        let result = collect_branch_list(tokio_stream::iter((0..10_000).map(branch)), Some(10_000))
            .await
            .unwrap()
            .expect("complete listing");
        assert_eq!(result.list.len(), 10_000);
        assert_eq!(result.list.first().unwrap().name, "0");
        assert_eq!(result.list.last().unwrap().name, "9999");
    }

    #[tokio::test]
    async fn over_limit_stops_consuming_the_stream() {
        let consumed = AtomicUsize::new(0);
        let stream = tokio_stream::iter((0..20_000).map(branch)).map(|item| {
            consumed.fetch_add(1, Ordering::Relaxed);
            item
        });
        let result = collect_branch_list(stream, Some(10_000)).await.unwrap();
        assert!(result.is_none(), "must report incomplete enumeration");
        assert_eq!(consumed.load(Ordering::Relaxed), 10_001);
    }

    #[tokio::test]
    async fn empty_and_zero_limit_are_distinguished_from_over_limit() {
        let empty = collect_branch_list(tokio_stream::iter(std::iter::empty()), Some(0))
            .await
            .unwrap()
            .unwrap();
        assert!(empty.list.is_empty());
        assert!(
            collect_branch_list(tokio_stream::iter([branch(0)]), Some(0))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn stream_failure_does_not_return_a_partial_listing() {
        let result = collect_branch_list(
            tokio_stream::iter([branch(0), Err(tonic::Status::unavailable("stream failed"))]),
            Some(10_000),
        )
        .await;
        assert_eq!(result.err().unwrap().code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn unbounded_listing_still_returns_every_branch() {
        let result = collect_branch_list(tokio_stream::iter((0..10_001).map(branch)), None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.list.len(), 10_001);
    }

    #[tokio::test]
    async fn absent_branch_messages_do_not_spend_branch_budget() {
        let result = collect_branch_list(
            tokio_stream::iter([Ok(proto::BranchListResponse { branch: None }), branch(0)]),
            Some(1),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.list.len(), 1);
        assert_eq!(result.list[0].name, "0");
    }
}

/// Upstream v0.14 branch-record tests, in their own module so their imports do not collide with
/// the managed-journal fixture above.
mod branch_records {
    use std::sync::Arc;
    use std::sync::Mutex;

    use lore_base::types::RepositoryId;
    use lore_proto::lore::model::v1 as model;
    use lore_proto::lore::revision::v1 as proto;
    use lore_proto::lore::revision::v1::revision_service_server::RevisionService as RevisionServiceV1;
    use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
    use lore_transport::grpc::GRPCAuth;
    use lore_transport::grpc::revision_client::RevisionService;
    use tonic::Request;
    use tonic::Response;
    use tonic::Status;
    use tonic::service::Routes;

    use crate::types::full_branch;

    /// A revision server that answers each branch get and create with [`Self::branch`], and records
    /// each branch listing request and answers it with no branches. It refuses every other request.
    struct BranchServer {
        branch: model::Branch,
        listed: Arc<Mutex<Vec<proto::BranchListRequest>>>,
    }

    #[tonic::async_trait]
    impl RevisionServiceV1 for BranchServer {
        async fn branch_create(
            &self,
            _: Request<proto::BranchCreateRequest>,
        ) -> Result<Response<proto::BranchCreateResponse>, Status> {
            Ok(Response::new(proto::BranchCreateResponse {
                branch: Some(self.branch.clone()),
            }))
        }

        async fn branch_delete(
            &self,
            _: Request<proto::BranchDeleteRequest>,
        ) -> Result<Response<proto::BranchDeleteResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn branch_get(
            &self,
            _: Request<proto::BranchGetRequest>,
        ) -> Result<Response<proto::BranchGetResponse>, Status> {
            Ok(Response::new(proto::BranchGetResponse {
                branch: Some(self.branch.clone()),
                // FORK-LOCAL (WP-120): no domain generation in this fixture.
                branch_generation: None,
            }))
        }

        type BranchListStream = tokio_stream::Empty<Result<proto::BranchListResponse, Status>>;

        async fn branch_list(
            &self,
            request: Request<proto::BranchListRequest>,
        ) -> Result<Response<Self::BranchListStream>, Status> {
            self.listed
                .lock()
                .expect("the listed requests' lock")
                .push(request.into_inner());
            Ok(Response::new(tokio_stream::empty()))
        }

        async fn branch_push(
            &self,
            _: Request<proto::BranchPushRequest>,
        ) -> Result<Response<proto::BranchPushResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn branch_metadata_get(
            &self,
            _: Request<proto::BranchMetadataGetRequest>,
        ) -> Result<Response<proto::BranchMetadataGetResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn branch_metadata_set(
            &self,
            _: Request<proto::BranchMetadataSetRequest>,
        ) -> Result<Response<proto::BranchMetadataSetResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn revision_list(
            &self,
            _: Request<proto::RevisionListRequest>,
        ) -> Result<Response<proto::RevisionListResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }
    }

    /// A revision client over a [`BranchServer`] that answers with `branch`, and the listing requests
    /// that server records.
    async fn start_branch_service(
        branch: model::Branch,
    ) -> (RevisionService, Arc<Mutex<Vec<proto::BranchListRequest>>>) {
        let server = BranchServer {
            branch,
            listed: Arc::default(),
        };
        let listed = server.listed.clone();
        let (_, channel) =
            super::super::serve_logged(Routes::new(RevisionServiceServer::new(server))).await;
        let auth = Arc::new(parking_lot::RwLock::new(GRPCAuth::default()));
        (
            RevisionService::new(channel, RepositoryId::default(), auth),
            listed,
        )
    }

    #[tokio::test]
    async fn branch_query_returns_every_field_of_the_answer() {
        let (branch, expected) = full_branch();
        let (service, _) = start_branch_service(branch).await;

        let record = service
            .branch_query(None, Some("feature"))
            .await
            .expect("the branch's record");

        assert_eq!(record, expected);
    }

    #[tokio::test]
    async fn a_query_by_id_keeps_the_queried_id_where_the_answer_has_none() {
        let (mut branch, expected) = full_branch();
        branch.id = Default::default();
        let (service, _) = start_branch_service(branch).await;

        let record = service
            .branch_query(Some(expected.id), None)
            .await
            .expect("the branch's record");

        assert_eq!(record, expected);
    }

    #[tokio::test]
    async fn branch_create_returns_every_field_of_the_answer() {
        let (branch, expected) = full_branch();
        let (service, _) = start_branch_service(branch).await;

        let record = service
            .branch_create(expected.id, "feature", "release", "alice", &expected.stack)
            .await
            .expect("the created branch's record");

        assert_eq!(record, expected);
    }

    #[tokio::test]
    async fn branch_list_sends_its_creator_and_include_deleted() {
        let (service, listed) = start_branch_service(model::Branch::default()).await;

        service
            .branch_list(Some("alice"), true)
            .await
            .expect("a filtered listing");
        service
            .branch_list(None, false)
            .await
            .expect("an unfiltered listing");

        assert_eq!(
            *listed.lock().expect("the listed requests' lock"),
            [
                proto::BranchListRequest {
                    creator: Some("alice".to_string()),
                    include_deleted: true,
                },
                proto::BranchListRequest {
                    creator: None,
                    include_deleted: false,
                },
            ]
        );
    }
}
