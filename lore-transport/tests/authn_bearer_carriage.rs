// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-120: `lore-authn-bearer` carriage across `lore-transport`'s gRPC clients.
//!
//! [CLIENT]-class, same reasoning as `lore-integration-tests/tests/grpc_mutation_dispatch_loss_test.rs`:
//! this exercises `lore-transport`'s gRPC clients against a real, in-process loopback `tonic`
//! server. The server implementations below are test-only scaffolding, not a change to any
//! production crate.
//!
//! `admin_client`, `lock_client`, `repository_client`, `revision_client`, and their client
//! structs (`AdminService`, `LockService`, `RepositoryService`, `RevisionService`) live in
//! private modules with no public re-export -- unreachable from an external test. The public
//! surface a caller outside this crate actually uses is [`lore_transport::connect`] plus
//! [`lore_transport::Connection::revision`]/`admin`/`lock`/`repository`, so that is the seam this
//! file drives, matching how `lore-revision` and `loreserver`'s own clients reach these verbs in
//! production.
//!
//! # Getting a non-empty `authentication_token`/`authorization_token` with no live auth server
//!
//! `lore_transport::connect`'s `identity_token`/`access_token` parameters are the caller-supplied
//! credentials `SuppliedCredentials` holds. Every layer between them and `GRPCAuth` short-circuits
//! to the supplied value verbatim when one is present, with no network call:
//! `lore_credential::token_store::load_user_token` returns a supplied `identity_token` immediately
//! (`if !identity_token.is_empty() { return Ok(identity_token.to_string()) }`), and
//! `lore_transport::auth::exchange::exchange` does the same for a supplied `access_token`
//! (`if !access_token.is_empty() { return Ok(access_token.to_string()) }`, checked before it ever
//! looks at `auth_url`). So supplying both turns `GRPCAuth::new`'s real `auth_exchange` into a
//! pure, offline derivation: `authentication_token == identity_token`,
//! `authorization_token == access_token`. This is what lets every test below run with no auth
//! endpoint at all (`Environment::default()`, matching `MinimalEnvironmentServer`) while still
//! observing two independently-controlled, non-empty bearer values.
//!
//! `repository` must be non-zero: `auth_exchange_for_identity` only calls `exchange()` (and so only
//! produces a non-empty `authorization_token`) `if !repository.is_zero()`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;
use lore_proto::AdminService as AdminServiceV1;
use lore_proto::AdminServiceServer;
use lore_proto::LockService as LockServiceV1;
use lore_proto::LockServiceServer;
use lore_proto::ObliterateRequest;
use lore_proto::ObliterateResponse;
use lore_proto::lock::AdminLockRequest;
use lore_proto::lock::AdminLockResponse;
use lore_proto::lock::ForceUnlockRequest;
use lore_proto::lock::ForceUnlockResponse;
use lore_proto::lock::LockRequest;
use lore_proto::lock::LockResponse;
use lore_proto::lock::QueryRequest;
use lore_proto::lock::QueryResponse;
use lore_proto::lock::StatusRequest;
use lore_proto::lock::StatusResponse;
use lore_proto::lock::UnlockRequest;
use lore_proto::lock::UnlockResponse;
use lore_proto::lore::environment::v1 as environment_v1;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentService as EnvironmentServiceV1;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentServiceServer;
use lore_proto::lore::repository::v1 as repository_v1;
use lore_proto::lore::repository::v1::repository_service_server::RepositoryService as RepositoryServiceV1;
use lore_proto::lore::repository::v1::repository_service_server::RepositoryServiceServer;
use lore_proto::lore::revision::v1 as revision_v1;
use lore_proto::lore::revision::v1::revision_service_server::RevisionService as RevisionServiceV1;
use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
use lore_proto::rpc::ServerInfoRequest;
use lore_proto::rpc::ServerInfoResponse;
use lore_transport::FencedLockResource;
use lore_transport::grpc::AUTHN_BEARER_METADATA_KEY;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::metadata::MetadataMap;

type ResponseStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send>>;

/// The repository every test connects with. Must be non-zero -- see the module doc comment.
fn test_repository() -> RepositoryId {
    RepositoryId::from([0x7Au8; 16])
}

/// What one recorded RPC call carried in its two bearer-shaped headers.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Captured {
    authn_bearer: Option<String>,
    authorization: Option<String>,
}

fn capture(metadata: &MetadataMap) -> Captured {
    Captured {
        authn_bearer: metadata
            .get(AUTHN_BEARER_METADATA_KEY)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        authorization: metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    }
}

type CaptureLog = Arc<Mutex<HashMap<&'static str, Captured>>>;

fn record(log: &CaptureLog, name: &'static str, metadata: &MetadataMap) {
    log.lock()
        .expect("capture log mutex poisoned")
        .insert(name, capture(metadata));
}

/// `lore_transport::connect` calls `EnvironmentService::EnvironmentGet` before anything else, to
/// learn the auth URL. An empty `Environment` (no `endpoint`) leaves every per-service URL and the
/// auth URL blank -- every service falls back to this same server's own address (see
/// `EnvironmentConfig::storage_url` et al.'s fallback contract), and the auth URL being blank is
/// exactly what makes the offline token derivation in the module doc comment apply.
struct RecordingEnvironment;

#[tonic::async_trait]
impl EnvironmentServiceV1 for RecordingEnvironment {
    async fn environment_get(
        &self,
        _request: Request<environment_v1::EnvironmentGetRequest>,
    ) -> Result<Response<environment_v1::EnvironmentGetResponse>, Status> {
        Ok(Response::new(environment_v1::EnvironmentGetResponse {
            environment: Some(environment_v1::Environment::default()),
        }))
    }
}

/// Implements only the RPCs this file dispatches; every other method returns `Unimplemented` and
/// is never called by these tests.
struct RecordingRevision {
    log: CaptureLog,
}

#[tonic::async_trait]
impl RevisionServiceV1 for RecordingRevision {
    async fn branch_create(
        &self,
        _request: Request<revision_v1::BranchCreateRequest>,
    ) -> Result<Response<revision_v1::BranchCreateResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn branch_delete(
        &self,
        request: Request<revision_v1::BranchDeleteRequest>,
    ) -> Result<Response<revision_v1::BranchDeleteResponse>, Status> {
        // Not one of the ten families the platform's operation verifier
        // accepts, but the client stamps the header anyway -- see
        // `revision_client.rs`'s own doc comment on this method. The server
        // still returns `Unimplemented`: what this test asserts is the request
        // that arrived, independent of the response.
        record(&self.log, "revision.branch_delete", request.metadata());
        Err(Status::unimplemented("not used by this test"))
    }

    async fn branch_get(
        &self,
        _request: Request<revision_v1::BranchGetRequest>,
    ) -> Result<Response<revision_v1::BranchGetResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    type BranchListStream = ResponseStream<revision_v1::BranchListResponse>;
    async fn branch_list(
        &self,
        request: Request<revision_v1::BranchListRequest>,
    ) -> Result<Response<Self::BranchListStream>, Status> {
        record(&self.log, "revision.branch_list", request.metadata());
        let empty: Self::BranchListStream = Box::pin(tokio_stream::empty());
        Ok(Response::new(empty))
    }

    async fn branch_push(
        &self,
        request: Request<revision_v1::BranchPushRequest>,
    ) -> Result<Response<revision_v1::BranchPushResponse>, Status> {
        record(&self.log, "revision.branch_push", request.metadata());
        Ok(Response::new(revision_v1::BranchPushResponse::default()))
    }

    async fn branch_metadata_get(
        &self,
        _request: Request<revision_v1::BranchMetadataGetRequest>,
    ) -> Result<Response<revision_v1::BranchMetadataGetResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn branch_metadata_set(
        &self,
        request: Request<revision_v1::BranchMetadataSetRequest>,
    ) -> Result<Response<revision_v1::BranchMetadataSetResponse>, Status> {
        record(
            &self.log,
            "revision.branch_metadata_set",
            request.metadata(),
        );
        Ok(Response::new(
            revision_v1::BranchMetadataSetResponse::default(),
        ))
    }

    async fn revision_list(
        &self,
        _request: Request<revision_v1::RevisionListRequest>,
    ) -> Result<Response<revision_v1::RevisionListResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }
}

struct RecordingRepository {
    log: CaptureLog,
}

#[tonic::async_trait]
impl RepositoryServiceV1 for RecordingRepository {
    async fn repository_create(
        &self,
        _request: Request<repository_v1::RepositoryCreateRequest>,
    ) -> Result<Response<repository_v1::RepositoryCreateResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn repository_delete(
        &self,
        request: Request<repository_v1::RepositoryDeleteRequest>,
    ) -> Result<Response<repository_v1::RepositoryDeleteResponse>, Status> {
        record(
            &self.log,
            "repository.repository_delete",
            request.metadata(),
        );
        Ok(Response::new(
            repository_v1::RepositoryDeleteResponse::default(),
        ))
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
        request: Request<repository_v1::RepositoryListRequest>,
    ) -> Result<Response<Self::RepositoryListStream>, Status> {
        record(&self.log, "repository.repository_list", request.metadata());
        let empty: Self::RepositoryListStream = Box::pin(tokio_stream::empty());
        Ok(Response::new(empty))
    }

    async fn repository_metadata_get(
        &self,
        _request: Request<repository_v1::RepositoryMetadataGetRequest>,
    ) -> Result<Response<repository_v1::RepositoryMetadataGetResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn repository_metadata_set(
        &self,
        request: Request<repository_v1::RepositoryMetadataSetRequest>,
    ) -> Result<Response<repository_v1::RepositoryMetadataSetResponse>, Status> {
        record(
            &self.log,
            "repository.repository_metadata_set",
            request.metadata(),
        );
        Ok(Response::new(
            repository_v1::RepositoryMetadataSetResponse::default(),
        ))
    }

    async fn repository_storage_stats(
        &self,
        _request: Request<repository_v1::RepositoryStorageStatsRequest>,
    ) -> Result<Response<repository_v1::RepositoryStorageStatsResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }
}

struct RecordingAdmin {
    log: CaptureLog,
}

#[tonic::async_trait]
impl AdminServiceV1 for RecordingAdmin {
    async fn server_info(
        &self,
        _request: Request<ServerInfoRequest>,
    ) -> Result<Response<ServerInfoResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn obliterate(
        &self,
        request: Request<ObliterateRequest>,
    ) -> Result<Response<ObliterateResponse>, Status> {
        record(&self.log, "admin.obliterate", request.metadata());
        Ok(Response::new(ObliterateResponse::default()))
    }
}

struct RecordingLock {
    log: CaptureLog,
}

#[tonic::async_trait]
impl LockServiceV1 for RecordingLock {
    async fn lock(&self, request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        record(&self.log, "lock.lock", request.metadata());
        Ok(Response::new(LockResponse::default()))
    }

    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        record(&self.log, "lock.query", request.metadata());
        Ok(Response::new(QueryResponse::default()))
    }

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        record(&self.log, "lock.unlock", request.metadata());
        Ok(Response::new(UnlockResponse::default()))
    }

    async fn admin_lock(
        &self,
        request: Request<AdminLockRequest>,
    ) -> Result<Response<AdminLockResponse>, Status> {
        record(&self.log, "lock.admin_lock", request.metadata());
        Ok(Response::new(AdminLockResponse::default()))
    }

    async fn force_unlock(
        &self,
        request: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        record(&self.log, "lock.force_unlock", request.metadata());
        Ok(Response::new(ForceUnlockResponse::default()))
    }
}

/// One ephemeral-port server, all five services registered on it, all sharing one capture log.
struct TestServer {
    addr: SocketAddr,
    log: CaptureLog,
}

impl TestServer {
    async fn start() -> Self {
        let log: CaptureLog = Arc::new(Mutex::new(HashMap::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let revision = RecordingRevision { log: log.clone() };
        let repository = RecordingRepository { log: log.clone() };
        let admin = RecordingAdmin { log: log.clone() };
        let lock = RecordingLock { log: log.clone() };

        // `lore_base::lore_spawn!` rather than a bare `tokio::spawn`: with a
        // `#[tokio::test]` runtime already current, `lore_base::runtime()`
        // returns that same runtime's handle (it only builds its own when none
        // is current), so the `TcpListener` bound above and the accept loop
        // below run on the one runtime it was registered on.
        lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(EnvironmentServiceServer::new(RecordingEnvironment))
                .add_service(RevisionServiceServer::new(revision))
                .add_service(RepositoryServiceServer::new(repository))
                .add_service(AdminServiceServer::new(admin))
                .add_service(LockServiceServer::new(lock))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("test server must not fail to serve");
        });

        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        Self { addr, log }
    }

    /// A real `lore_transport::connect` against this server, with the given supplied
    /// credentials. `identity` is a fixed, arbitrary non-empty human handle -- distinct from
    /// `identity_token`/`access_token`, which are the actual bearer values under test.
    async fn connect(
        &self,
        identity_token: &str,
        access_token: &str,
    ) -> Arc<lore_transport::Connection> {
        lore_transport::connect(
            &format!("grpc://{}", self.addr),
            "wp120-authn-bearer-test-identity",
            test_repository(),
            1,
            identity_token,
            access_token,
        )
        .await
        .expect("connect must succeed against the in-process test server")
    }

    fn captured(&self, name: &str) -> Option<Captured> {
        self.log
            .lock()
            .expect("capture log mutex poisoned")
            .get(name)
            .cloned()
    }
}

const AUTHN_TOKEN: &str = "test-authn-jwt";
const AUTHZ_TOKEN: &str = "test-authz-token";

fn expected_authn_header() -> String {
    format!("Bearer {AUTHN_TOKEN}")
}

fn expected_authz_header() -> String {
    format!("Bearer {AUTHZ_TOKEN}")
}

fn one_fenced_resource() -> Vec<FencedLockResource> {
    vec![FencedLockResource::tokenless(LockResource {
        branch: Context::from([0x02u8; 16]),
        hash: Hash::from([0x55u8; 32]),
        description: "wp120-test-resource".to_string(),
    })]
}

fn one_plain_resource() -> Vec<LockResource> {
    vec![LockResource {
        branch: Context::from([0x02u8; 16]),
        hash: Hash::from([0x55u8; 32]),
        description: "wp120-test-resource".to_string(),
    }]
}

// ---------------------------------------------------------------------------------------
// Governed mutations: nine dispatch sites now carry the header --
// `branch_delete` joined the other eight after this round's fix, since its
// handler also calls `admit_at_entry` (WP-116 writer inventory B4) even
// though it is not one of the ten families the platform's operation verifier
// itself accepts. Each dispatch below must carry
// `lore-authn-bearer == "Bearer <authn token>"`.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn branch_push_carries_the_authn_bearer_and_authorization_carries_the_authz_token() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let revision = connection
        .revision(test_repository())
        .await
        .expect("revision client");

    revision
        .branch_push(
            Context::from([0x03u8; 16]),
            Hash::from([0x01u8; 32]),
            false,
            false,
        )
        .await
        .expect("branch_push must succeed");

    let captured = server
        .captured("revision.branch_push")
        .expect("branch_push must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    // `RevisionService` runs under `AuthzInterceptor`: `authorization` carries the exchanged
    // AUTHZ token, independently of `lore-authn-bearer`.
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

#[tokio::test]
async fn branch_metadata_set_carries_the_authn_bearer_and_authorization_carries_the_authz_token() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let revision = connection
        .revision(test_repository())
        .await
        .expect("revision client");

    revision
        .branch_metadata_set(
            Context::from([0x03u8; 16]),
            Hash::from([0x01u8; 32]),
            Hash::from([0x02u8; 32]),
        )
        .await
        .expect("branch_metadata_set must succeed");

    let captured = server
        .captured("revision.branch_metadata_set")
        .expect("branch_metadata_set must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

// The ninth dispatch site: `branch_delete` is not one of the ten families the
// platform's operation verifier accepts, but its handler calls
// `admit_at_entry` exactly as `branch_push` does, so it carries the header
// too. The server refuses the call (`Unimplemented`); this asserts the
// request it received, independent of that refusal.
#[tokio::test]
async fn branch_delete_carries_the_authn_bearer_and_authorization_carries_the_authz_token() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let revision = connection
        .revision(test_repository())
        .await
        .expect("revision client");

    let _ = revision.branch_delete(Context::from([0x03u8; 16])).await;

    let captured = server
        .captured("revision.branch_delete")
        .expect("branch_delete must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

#[tokio::test]
async fn repository_delete_carries_the_authn_bearer_and_authorization_carries_the_same_authn_token()
{
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let repository = connection.repository().await.expect("repository client");

    repository
        .delete(test_repository())
        .await
        .expect("delete must succeed");

    let captured = server
        .captured("repository.repository_delete")
        .expect("repository_delete must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    // `RepositoryService` runs under `AuthnInterceptor`, not `AuthzInterceptor`: its
    // `authorization` already carries the AUTHN token, so the two headers coincide here by
    // design -- unlike every `AuthzInterceptor` verb above, where they differ.
    assert_eq!(captured.authorization, Some(expected_authn_header()));
}

#[tokio::test]
async fn repository_metadata_set_carries_the_authn_bearer_and_authorization_carries_the_same_authn_token()
 {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let repository = connection.repository().await.expect("repository client");

    repository
        .metadata_set(
            test_repository(),
            Hash::from([0x01u8; 32]),
            Hash::from([0x02u8; 32]),
        )
        .await
        .expect("metadata_set must succeed");

    let captured = server
        .captured("repository.repository_metadata_set")
        .expect("repository_metadata_set must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authn_header()));
}

#[tokio::test]
async fn obliterate_carries_the_authn_bearer_and_authorization_carries_the_authz_token() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let admin = connection
        .admin(test_repository())
        .await
        .expect("admin client");

    admin
        .obliterate(Address::default())
        .await
        .expect("obliterate must succeed");

    let captured = server
        .captured("admin.obliterate")
        .expect("obliterate must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

#[tokio::test]
async fn lock_without_an_owner_dispatches_lock_carrying_the_authn_bearer() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let lock = connection
        .lock(test_repository())
        .await
        .expect("lock client");

    lock.lock(&one_fenced_resource(), None)
        .await
        .expect("lock must succeed");

    let captured = server
        .captured("lock.lock")
        .expect("lock must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

#[tokio::test]
async fn lock_with_an_owner_dispatches_admin_lock_carrying_the_authn_bearer() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let lock = connection
        .lock(test_repository())
        .await
        .expect("lock client");

    lock.lock(&one_fenced_resource(), Some("some-other-owner"))
        .await
        .expect("admin_lock must succeed");

    let captured = server
        .captured("lock.admin_lock")
        .expect("admin_lock must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

#[tokio::test]
async fn unlock_carries_the_authn_bearer_and_authorization_carries_the_authz_token() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let lock = connection
        .lock(test_repository())
        .await
        .expect("lock client");

    lock.unlock(&one_fenced_resource())
        .await
        .expect("unlock must succeed");

    let captured = server
        .captured("lock.unlock")
        .expect("unlock must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

#[tokio::test]
async fn force_unlock_carries_the_authn_bearer_and_authorization_carries_the_authz_token() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let lock = connection
        .lock(test_repository())
        .await
        .expect("lock client");

    lock.force_unlock(&one_plain_resource(), "some-other-owner")
        .await
        .expect("force_unlock must succeed");

    let captured = server
        .captured("lock.force_unlock")
        .expect("force_unlock must have been recorded");
    assert_eq!(captured.authn_bearer, Some(expected_authn_header()));
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

// ---------------------------------------------------------------------------------------
// Reads: never carry `lore-authn-bearer`, one per client.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn branch_list_carries_no_authn_bearer_header() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let revision = connection
        .revision(test_repository())
        .await
        .expect("revision client");

    revision
        .branch_list()
        .await
        .expect("branch_list must succeed");

    let captured = server
        .captured("revision.branch_list")
        .expect("branch_list must have been recorded");
    assert_eq!(captured.authn_bearer, None);
}

#[tokio::test]
async fn repository_list_carries_no_authn_bearer_header() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let repository = connection.repository().await.expect("repository client");

    repository.list().await.expect("list must succeed");

    let captured = server
        .captured("repository.repository_list")
        .expect("repository_list must have been recorded");
    assert_eq!(captured.authn_bearer, None);
}

#[tokio::test]
async fn lock_query_carries_no_authn_bearer_header() {
    let server = TestServer::start().await;
    let connection = server.connect(AUTHN_TOKEN, AUTHZ_TOKEN).await;
    let lock = connection
        .lock(test_repository())
        .await
        .expect("lock client");

    lock.query(None, None, None)
        .await
        .expect("query must succeed");

    let captured = server
        .captured("lock.query")
        .expect("query must have been recorded");
    assert_eq!(captured.authn_bearer, None);
}

// ---------------------------------------------------------------------------------------
// The service-delegation / raw-supplied-token case: no authentication token to send.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_governed_mutation_with_no_authentication_token_carries_no_authn_bearer_header() {
    let server = TestServer::start().await;
    // Empty `identity_token`, non-empty `access_token`: the caller has an authorization but no
    // human authentication bearer to forward. See the module doc comment for exactly which
    // early-return this exercises in `auth_exchange_for_identity`/`token_store::load_user_token`.
    let connection = server.connect("", AUTHZ_TOKEN).await;
    let revision = connection
        .revision(test_repository())
        .await
        .expect("revision client");

    revision
        .branch_push(
            Context::from([0x03u8; 16]),
            Hash::from([0x01u8; 32]),
            false,
            false,
        )
        .await
        .expect("branch_push must still succeed with no authentication token");

    let captured = server
        .captured("revision.branch_push")
        .expect("branch_push must have been recorded");
    assert_eq!(
        captured.authn_bearer, None,
        "inject_authn_bearer is a silent no-op when the credential store holds no \
         authentication token"
    );
    // `authorization` is unaffected: the exchanged AUTHZ token is still present.
    assert_eq!(captured.authorization, Some(expected_authz_header()));
}

// ---------------------------------------------------------------------------------------
// Credential hygiene: the injected value must be marked sensitive, and that must actually
// redact it in the Debug output of the real type `RequestLoggerService`'s
// `lore_debug!("gRPC request: {req:?}")` formats.
// ---------------------------------------------------------------------------------------

#[test]
fn inject_authn_bearer_marks_the_header_sensitive_and_a_real_http_request_debug_redacts_it() {
    let auth: lore_transport::grpc::GRPCAuthRef =
        Arc::new(parking_lot::RwLock::new(lore_transport::grpc::GRPCAuth {
            authentication_token: AUTHN_TOKEN.to_string(),
            ..Default::default()
        }));
    let mut request = tonic::Request::new(());

    lore_transport::grpc::inject_authn_bearer(&mut request, &auth)
        .expect("a well-formed token must inject cleanly");

    let value = request
        .metadata()
        .get(AUTHN_BEARER_METADATA_KEY)
        .expect("the header must be present");
    assert!(
        value.is_sensitive(),
        "the injected lore-authn-bearer value must be marked sensitive"
    );

    // The flag alone is not the story -- prove the redaction end to end.
    // `MetadataMap::into_headers` is the exact conversion tonic performs when it actually
    // dispatches a call, producing real `http::HeaderValue`s that carry the sensitivity bit
    // (`tonic::metadata::MetadataValue` is a thin wrapper over `http::HeaderValue`). Building a
    // genuine `http::Request` from them and Debug-formatting it is what
    // `RequestLoggerService::call`'s `lore_debug!("gRPC request: {req:?}")` does in production.
    let headers = request.metadata().clone().into_headers();
    let mut http_request = http::Request::builder()
        .method("POST")
        .uri("http://example.invalid/x")
        .body(())
        .expect("a minimal http::Request must build");
    *http_request.headers_mut() = headers;

    let debug = format!("{http_request:?}");
    assert!(
        debug.contains("Sensitive"),
        "a sensitive header must render as \"Sensitive\" in http::Request's Debug: {debug}"
    );
    assert!(
        !debug.contains(AUTHN_TOKEN),
        "the raw bearer value must never appear in a Debug-formatted request: {debug}"
    );
}

// ---------------------------------------------------------------------------------------
// Client/server literal pin.
// ---------------------------------------------------------------------------------------

/// `lore-transport` cannot depend on `lore-server`, so its own
/// `AUTHN_BEARER_METADATA_KEY` and the server's `domain_operation_metadata::AUTHN_BEARER_KEY`
/// (`lore-server/src/grpc/domain_operation_metadata.rs:102`) are kept equal by a literal plus a
/// source-location comment on each side rather than a shared symbol -- mirrored on the server
/// side by `lore-server/tests/wp120_authn_bearer.rs`'s own literal-pin test.
#[test]
fn the_authn_bearer_metadata_key_is_the_literal_the_server_pins_against() {
    assert_eq!(AUTHN_BEARER_METADATA_KEY, "lore-authn-bearer");
}
