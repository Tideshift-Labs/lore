// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! A live-connected repository fixture (WP-120).
//!
//! Every `RepositoryContext` this crate's test harness builds resolves its remote to
//! `Err(NoRemote)`, so nothing below the transport could ever be driven against a server that
//! answers. `docs/testing-guide.md` recorded that gap and priced closing it as a real feature
//! addition rather than a cheap extension; this module is that addition. What it produces is an
//! ordinary on-disk repository whose config names a remote, opened through the production
//! [`crate::repository::load_and_connect`] path, so its `remote()` resolves to `Connected` after
//! a real handshake rather than by having a `Connection` handed to it.
//!
//! **The remote is an in-process `tonic` server, not an in-process loreserver, and that choice is
//! forced rather than preferred.** `lore-server` depends on `lore-revision`, so a fixture living
//! here cannot build one without inverting the dependency. `lore_transport::connect` accepts a
//! `grpc://` URL and the shape below is the one
//! `lore-transport/src/grpc/storage_client.rs`'s own tests and
//! `lore-integration-tests/tests/grpc_mutation_dispatch_loss_test.rs` already use: bind an
//! ephemeral loopback port, serve the handful of services the path under test reaches, and let
//! everything else answer `Unimplemented`.
//!
//! Behind `test_seams` for the reason that feature exists — production must never link it. The
//! feature is enabled for `lore`'s dev build the same way `lore-transport`'s already is.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

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
use lore_proto::lock::lock_service_server::LockService;
use lore_proto::lock::lock_service_server::LockServiceServer;
use lore_proto::lore::environment::v1 as environment_v1;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentService;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentServiceServer;
use lore_transport::outcome::ATTEMPT_ID_METADATA_KEY;
use parking_lot::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::interface::LoreArray;
use crate::interface::LoreString;
use crate::lore::RepositoryId;
use crate::repository::RepositoryAccess;
use crate::repository::RepositoryConfig;
use crate::repository::RepositoryContext;
use crate::repository::RepositoryWriteToken;

/// Which lock RPC one recorded call came through.
///
/// Named rather than a string because the three that mutate are the ones a caller journals, and a
/// test asserting "the force-release was journalled too" should not be able to pass by matching a
/// substring of a different RPC's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockRpc {
    Lock,
    AdminLock,
    Unlock,
    ForceUnlock,
    Query,
    Status,
}

/// One request the stub server actually received.
///
/// `attempt_id` is read off the `lore-attempt-id` request header, which
/// `lore_transport::grpc::AuthzInterceptor` stamps from whatever dispatch attempt is in scope. It
/// is the wire-side half of the claim the attempt store makes on the client side, and holding both
/// is what turns "the store has a record" into "the id the caller wrote down is the id that
/// reached the server".
#[derive(Clone, Debug)]
pub struct LockCall {
    pub rpc: LockRpc,
    pub attempt_id: Option<String>,
    /// The `description` of every resource in the request, in wire order.
    pub descriptions: Vec<String>,
    /// The owner named by an `AdminLock` or `ForceUnlock`, empty otherwise.
    pub owner: String,
    /// Whether every resource in the request carried an ownership token.
    pub all_resources_carried_a_token: bool,
}

/// How the stub answers one RPC.
#[derive(Clone, Debug)]
pub enum RpcOutcome {
    /// Answer successfully.
    Grant,
    /// Answer with this status. Only `ResourceExhausted` is retried by the client; every other
    /// code fails the call on the first answer, which is what makes a failure fixture bounded.
    Refuse(tonic::Code, String),
}

/// The stub's per-RPC policy, changeable while the server is running.
#[derive(Clone, Debug)]
pub struct LockPolicy {
    pub lock: RpcOutcome,
    pub admin_lock: RpcOutcome,
    pub unlock: RpcOutcome,
    pub force_unlock: RpcOutcome,
    /// Whether a granted lock carries a 32-byte ownership token. A cell that is not routing
    /// through the fenced authority returns none, and both shapes are legitimate, so both are
    /// reachable here.
    pub mint_ownership_tokens: bool,
    /// Which of the requested resources a successful `Unlock` reports as released.
    ///
    /// A partial answer is the shape that discriminates the release accounting: the client clears
    /// ownership for what the server named and for nothing else, so a fixture that can only answer
    /// "all" cannot tell a correct implementation from one that clears the whole request.
    pub unlock_echo: UnlockEcho,
    /// What `Query` reports, as `(description, owner)` pairs. Only these two fields are read by
    /// the release path — it rebuilds the resource from the description itself — so the rest of
    /// the row is left at its default.
    pub query_result: Vec<(String, String)>,
}

/// How much of an `Unlock` request a successful answer confirms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockEcho {
    /// Confirm every resource in the request.
    All,
    /// Confirm only the first resource in the request, leaving the rest unconfirmed.
    FirstOnly,
    /// Confirm nothing, while still answering successfully.
    None,
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self {
            lock: RpcOutcome::Grant,
            admin_lock: RpcOutcome::Grant,
            unlock: RpcOutcome::Grant,
            force_unlock: RpcOutcome::Grant,
            mint_ownership_tokens: true,
            unlock_echo: UnlockEcho::All,
            query_result: Vec::new(),
        }
    }
}

#[derive(Default)]
struct ServerState {
    calls: Mutex<Vec<LockCall>>,
    policy: Mutex<LockPolicy>,
    /// Monotonic counter feeding minted ownership tokens, so two granted rows never share one.
    minted: Mutex<u64>,
}

/// A running in-process lock server, plus everything a test needs to interrogate it.
///
/// Aborting the accept loop on drop is deliberate but not load-bearing: the ephemeral port is
/// released when the process ends either way, and no test here severs a connection.
pub struct LockServer {
    addr: SocketAddr,
    state: Arc<ServerState>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for LockServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl LockServer {
    /// Bind an ephemeral loopback port and serve the environment and lock services on it.
    ///
    /// The environment service is not optional scaffolding. `lore_transport::connect` calls
    /// `EnvironmentGet` before it hands back a connection, and a server that does not implement it
    /// answers `Unimplemented`, which the client classifies as `NotSupported` and fails the whole
    /// connect on — so a fixture without it fails during setup for a reason unrelated to what it
    /// is testing. An empty `Environment` leaves the auth URL blank, which is what makes `connect`
    /// skip the token exchange.
    pub async fn start() -> Self {
        Self::start_with_policy(LockPolicy::default()).await
    }

    pub async fn start_with_policy(policy: LockPolicy) -> Self {
        let state = Arc::new(ServerState {
            calls: Mutex::new(Vec::new()),
            policy: Mutex::new(policy),
            minted: Mutex::new(0),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port for the lock fixture");
        let addr = listener
            .local_addr()
            .expect("reading the fixture server's local address");

        let service = StubLockService {
            state: state.clone(),
        };

        #[allow(clippy::disallowed_methods)] // Test-local server task.
        let handle = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(LockServiceServer::new(service))
                .add_service(EnvironmentServiceServer::new(StubEnvironmentService))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await;
        });

        // The client's first connect fails outright rather than retrying if the listener is not
        // accepting yet, so wait for it here rather than making every caller carry a retry.
        for _ in 0..200u32 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        Self {
            addr,
            state,
            handle,
        }
    }

    /// The URL to put in a repository's config so it connects here.
    pub fn remote_url(&self) -> String {
        format!("grpc://{}", self.addr)
    }

    /// Every request the server received, in arrival order.
    pub fn calls(&self) -> Vec<LockCall> {
        self.state.calls.lock().clone()
    }

    /// Only the requests that came through `rpc`.
    pub fn calls_for(&self, rpc: LockRpc) -> Vec<LockCall> {
        self.state
            .calls
            .lock()
            .iter()
            .filter(|call| call.rpc == rpc)
            .cloned()
            .collect()
    }

    /// Change how the server answers, mid-test.
    pub fn set_policy(&self, policy: LockPolicy) {
        *self.state.policy.lock() = policy;
    }

    /// A cheap, cloneable read handle on what the server has seen.
    ///
    /// Exists so a test double on the *client* side — an attempt store that records when it was
    /// called — can ask what the server had received at that moment. That comparison is what turns
    /// "the store holds a record" into "the record was written before the request left", which is
    /// the ordering the whole feature rests on and the one a snapshot taken at the end cannot see.
    pub fn probe(&self) -> LockServerProbe {
        LockServerProbe(self.state.clone())
    }
}

/// A read-only handle on a running [`LockServer`]'s received requests.
#[derive(Clone)]
pub struct LockServerProbe(Arc<ServerState>);

impl LockServerProbe {
    pub fn calls(&self) -> Vec<LockCall> {
        self.0.calls.lock().clone()
    }

    pub fn call_count(&self) -> usize {
        self.0.calls.lock().len()
    }
}

struct StubEnvironmentService;

#[tonic::async_trait]
impl EnvironmentService for StubEnvironmentService {
    async fn environment_get(
        &self,
        _request: Request<environment_v1::EnvironmentGetRequest>,
    ) -> Result<Response<environment_v1::EnvironmentGetResponse>, Status> {
        Ok(Response::new(environment_v1::EnvironmentGetResponse {
            environment: Some(environment_v1::Environment::default()),
        }))
    }
}

struct StubLockService {
    state: Arc<ServerState>,
}

impl StubLockService {
    fn record<T>(
        &self,
        rpc: LockRpc,
        request: &Request<T>,
        resources: &[lore_proto::lock::Resource],
        owner: &str,
    ) {
        let attempt_id = request
            .metadata()
            .get(ATTEMPT_ID_METADATA_KEY)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        self.state.calls.lock().push(LockCall {
            rpc,
            attempt_id,
            descriptions: resources
                .iter()
                .map(|resource| resource.description.clone())
                .collect(),
            owner: owner.to_owned(),
            all_resources_carried_a_token: !resources.is_empty()
                && resources
                    .iter()
                    .all(|resource| !resource.expected_ownership_token.is_empty()),
        });
    }

    /// Grant every requested resource, minting a distinct token per row when the policy says the
    /// cell is fenced.
    fn grant(
        &self,
        resources: Vec<lore_proto::lock::Resource>,
        owner: &str,
    ) -> Vec<lore_proto::lock::Lock> {
        let mint = self.state.policy.lock().mint_ownership_tokens;
        resources
            .into_iter()
            .map(|mut resource| {
                // The request-side token is the caller's evidence, not part of the granted row.
                resource.expected_ownership_token = Vec::new().into();
                let ownership_token = if mint {
                    let mut counter = self.state.minted.lock();
                    *counter += 1;
                    let mut token = vec![0u8; 32];
                    token[..8].copy_from_slice(&counter.to_be_bytes());
                    token
                } else {
                    Vec::new()
                };
                lore_proto::lock::Lock {
                    resource: Some(resource),
                    owner: owner.to_owned(),
                    locked_at: None,
                    ownership_token: ownership_token.into(),
                }
            })
            .collect()
    }

    fn outcome(&self, rpc: LockRpc) -> RpcOutcome {
        let policy = self.state.policy.lock();
        match rpc {
            LockRpc::Lock => policy.lock.clone(),
            LockRpc::AdminLock => policy.admin_lock.clone(),
            LockRpc::Unlock => policy.unlock.clone(),
            LockRpc::ForceUnlock => policy.force_unlock.clone(),
            LockRpc::Query | LockRpc::Status => RpcOutcome::Grant,
        }
    }
}

#[tonic::async_trait]
impl LockService for StubLockService {
    async fn lock(&self, request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        let resources = request.get_ref().resources.clone();
        self.record(LockRpc::Lock, &request, &resources, "");
        match self.outcome(LockRpc::Lock) {
            RpcOutcome::Refuse(code, message) => Err(Status::new(code, message)),
            RpcOutcome::Grant => Ok(Response::new(LockResponse {
                locks: self.grant(resources, "fixture-owner"),
            })),
        }
    }

    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        self.record(LockRpc::Query, &request, &[], "");
        let rows = self.state.policy.lock().query_result.clone();
        Ok(Response::new(QueryResponse {
            result: rows
                .into_iter()
                .map(|(description, owner)| lore_proto::lock::Lock {
                    resource: Some(lore_proto::lock::Resource {
                        description,
                        ..lore_proto::lock::Resource::default()
                    }),
                    owner,
                    locked_at: None,
                    ownership_token: Vec::new().into(),
                })
                .collect(),
        }))
    }

    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let resources = request.get_ref().resources.clone();
        self.record(LockRpc::Status, &request, &resources, "");
        Ok(Response::new(StatusResponse { locks: Vec::new() }))
    }

    async fn unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        let resources = request.get_ref().resources.clone();
        self.record(LockRpc::Unlock, &request, &resources, "");
        match self.outcome(LockRpc::Unlock) {
            RpcOutcome::Refuse(code, message) => Err(Status::new(code, message)),
            RpcOutcome::Grant => {
                let echo = self.state.policy.lock().unlock_echo;
                let confirmed = match echo {
                    UnlockEcho::All => resources,
                    UnlockEcho::FirstOnly => resources.into_iter().take(1).collect(),
                    UnlockEcho::None => Vec::new(),
                };
                Ok(Response::new(UnlockResponse {
                    resources: confirmed,
                }))
            }
        }
    }

    async fn admin_lock(
        &self,
        request: Request<AdminLockRequest>,
    ) -> Result<Response<AdminLockResponse>, Status> {
        let resources = request.get_ref().resources.clone();
        let owner = request.get_ref().owner.clone();
        self.record(LockRpc::AdminLock, &request, &resources, &owner);
        match self.outcome(LockRpc::AdminLock) {
            RpcOutcome::Refuse(code, message) => Err(Status::new(code, message)),
            RpcOutcome::Grant => Ok(Response::new(AdminLockResponse {
                locks: self.grant(resources, &owner),
            })),
        }
    }

    async fn force_unlock(
        &self,
        request: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        let resources = request.get_ref().resources.clone();
        let owner = request.get_ref().owner.clone();
        self.record(LockRpc::ForceUnlock, &request, &resources, &owner);
        match self.outcome(LockRpc::ForceUnlock) {
            RpcOutcome::Refuse(code, message) => Err(Status::new(code, message)),
            RpcOutcome::Grant => Ok(Response::new(ForceUnlockResponse { resources })),
        }
    }
}

/// A temporary directory removed on drop.
///
/// Local rather than `tempfile`, because this module is behind a feature that a non-test build of
/// `lore` still resolves dependencies for, and a dev-dependency cannot be reached from `src/`.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        use rand::distr::SampleString;
        let name = format!(
            "{prefix}{}",
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 12)
        );
        let path = std::env::temp_dir().join(name);
        // Fixture directory creation; not subject to repository write-token discipline.
        #[allow(clippy::disallowed_methods)]
        std::fs::create_dir_all(&path).expect("creating the fixture directory");
        #[allow(clippy::disallowed_methods)]
        let path = std::fs::canonicalize(path).expect("canonicalizing the fixture directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Fixture cleanup; not subject to repository write-token discipline.
        #[allow(clippy::disallowed_methods)]
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An on-disk repository with one committed file, configured to reach a live remote.
///
/// The directory outlives every use of the repository, so keep this value alive for the whole
/// test. `path` is what a `lore`-crate entry point wants in its `LoreGlobalArgs`; `connect` is
/// what a `lore-revision` entry point wants.
pub struct LiveRepository {
    pub path: PathBuf,
    pub repository_id: RepositoryId,
    /// The committed files, relative to the repository root, in the form the lock verbs report
    /// them.
    pub committed_files: Vec<String>,
    /// The same files as absolute paths, for a caller building `LoreArray` arguments.
    pub committed_files_absolute: Vec<PathBuf>,
    pub remote_url: String,
    _tempdir: TempDir,
}

impl LiveRepository {
    /// Create a repository whose config names `remote_url`, and commit one file into it.
    ///
    /// Must be called inside a `LORE_CONTEXT` scope: repository creation, staging, and commit all
    /// read the execution context.
    ///
    /// The commit is not decoration. A lock acquire resolves every requested path against the
    /// committed state and refuses a path with no valid node link, so a repository with no
    /// revision cannot reach a single lock dispatch — which is exactly why the offline harness
    /// could not host these proofs.
    pub async fn create(remote_url: &str) -> Self {
        Self::create_with_files(remote_url, &["locked.file"]).await
    }

    /// As [`Self::create`], with one committed file per name given.
    ///
    /// Several files matter for the release accounting: a server that confirms one of two
    /// requested releases is the only shape that can tell "clears what the server named" apart
    /// from "clears the whole request".
    pub async fn create_with_files(remote_url: &str, names: &[&str]) -> Self {
        let tempdir = TempDir::new("lore-live-fixture-");
        let path = tempdir.path().to_path_buf();
        let repository_id = RepositoryId::from(uuid::Uuid::now_v7());
        let default_branch = crate::lore::BranchId::from(uuid::Uuid::now_v7());

        let token = RepositoryWriteToken::acquire(path.as_path()).await;
        let repository = crate::repository::create_local(
            path.as_path(),
            &token,
            repository_id,
            default_branch,
            crate::branch::DEFAULT_DEFAULT_NAME.to_string(),
            RepositoryConfig {
                remote_url: Some(remote_url.to_owned()),
                ..RepositoryConfig::default()
            },
            false,
        )
        .await
        .expect("creating the fixture repository");

        let mut committed_files_absolute = Vec::with_capacity(names.len());
        for (index, name) in names.iter().enumerate() {
            let absolute = path.join(name);
            {
                use std::io::Write;
                // Fixture file write; not subject to repository write-token discipline.
                #[allow(clippy::disallowed_methods)]
                let mut file = std::fs::File::options()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(absolute.as_path())
                    .expect("creating the fixture file");
                // Distinct content per file so no two share a content hash, which would make two
                // lock resources collide and hide a per-resource accounting bug.
                write!(file, "live fixture payload {index}").expect("writing the fixture file");
            }
            committed_files_absolute.push(absolute);
        }

        crate::file::stage::stage(
            repository.clone(),
            &token,
            LoreArray::from_vec(
                committed_files_absolute
                    .iter()
                    .map(LoreString::from)
                    .collect(),
            ),
            crate::stage::StageOptions {
                case_change: crate::stage::StageCaseChange::Error,
                node_flags: crate::node::NodeFlags::NoFlags,
                file_id: None,
                no_children: false,
                scan: true,
            },
        )
        .await
        .expect("staging the fixture file");

        Box::pin(crate::commit::commit(
            repository.clone(),
            &token,
            crate::commit::CommitOptions {
                message: "live fixture".to_owned(),
                link_messages: HashMap::new(),
                link: None,
                layer_messages: HashMap::new(),
                layer: None,
                stats: false,
            },
        ))
        .await
        .expect("committing the fixture revision");

        repository
            .flush(true)
            .await
            .expect("flushing the fixture repository");

        // Dropped before any caller opens the same path: the write token is a per-path mutex, and
        // holding it here would deadlock `load_and_connect`'s own acquisition.
        drop(repository);
        drop(token);

        Self {
            path,
            repository_id,
            committed_files: names.iter().map(|name| (*name).to_owned()).collect(),
            committed_files_absolute,
            remote_url: remote_url.to_owned(),
            _tempdir: tempdir,
        }
    }

    /// Global arguments naming this repository, for a `lore`-crate entry point.
    pub fn globals(&self) -> crate::interface::LoreGlobalArgs {
        crate::interface::LoreGlobalArgs {
            repository_path: LoreString::from(&self.path),
            ..crate::interface::LoreGlobalArgs::default()
        }
    }

    /// Open the repository through the production path, with its remote resolved for real.
    ///
    /// This is the fixture the testing guide was asking for. The returned context's `remote()`
    /// completes the `grpc://` handshake against the running stub and promotes to `Connected`,
    /// rather than being handed a `Connection` it did not open — so a caller exercising a code
    /// path that reads `remote()` exercises the same resolution production does.
    pub async fn connect(&self, access: RepositoryAccess) -> Arc<RepositoryContext> {
        crate::repository::load_and_connect(self.path.as_path(), access)
            .await
            .expect("opening the fixture repository")
    }
}

/// An execution context suitable for driving the fixture, with no event dispatch.
pub fn fixture_execution_context() -> Arc<crate::interface::ExecutionContext> {
    Arc::new(crate::interface::ExecutionContext::new_client_with_user_id(
        crate::interface::LoreGlobalArgs::default(),
        crate::relay::EventDispatcher::no_dispatch(),
        "live-fixture-user".to_string(),
    ))
}
