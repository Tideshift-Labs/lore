// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! CR-030, WP-120: `lock_client::LockService`'s wire-level ownership-token wiring, over the same
//! real in-process tonic double pattern `attempt_id_wire_tests` uses. Deliberately a sibling
//! module rather than an extension of `RecordingLockServer` -- that double's whole point is
//! capturing the `lore-attempt-id` header, and it never populates a wire token; conflating the
//! two concerns in one double would make a change to either one risk breaking tests that have
//! nothing to do with it.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;
use lore_proto::lock::AdminLockRequest;
use lore_proto::lock::AdminLockResponse;
use lore_proto::lock::ForceUnlockRequest;
use lore_proto::lock::ForceUnlockResponse;
use lore_proto::lock::Lock as WireLock;
use lore_proto::lock::LockRequest;
use lore_proto::lock::LockResponse;
use lore_proto::lock::QueryRequest;
use lore_proto::lock::QueryResponse;
use lore_proto::lock::StatusRequest;
use lore_proto::lock::StatusResponse;
use lore_proto::lock::UnlockRequest;
use lore_proto::lock::UnlockResponse;
use lore_proto::lock::lock_service_server::LockService as LockServiceServerTrait;
use lore_proto::lock::lock_service_server::LockServiceServer;
use lore_transport::attempt_store::FencedLockResource;
use lore_transport::attempt_store::OwnershipToken;
use lore_transport::grpc::GRPCAuth;
use lore_transport::grpc::GRPCAuthRef;
use lore_transport::grpc::RequestLoggerLayer;
use lore_transport::grpc::lock_client;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tower::ServiceBuilder;

const MINTED_TOKEN: [u8; OwnershipToken::LEN] = [0x9Cu8; OwnershipToken::LEN];

fn one_resource() -> LockResource {
    LockResource {
        branch: Context::from([0x02u8; 16]),
        hash: Hash::from([0x55u8; 32]),
        description: "test-resource".to_string(),
    }
}

/// Implements only `lock`, `unlock`, and `force_unlock`, and records exactly what each wire
/// request carried in its `expected_ownership_token`/`owner` field. `lock` always grants and
/// mints [`MINTED_TOKEN`], as a fenced coordinator would.
struct TokenRecordingLockServer {
    seen_lock_tokens: Arc<Mutex<Vec<Bytes>>>,
    seen_unlock_tokens: Arc<Mutex<Vec<Bytes>>>,
    seen_force_unlock_owner: Arc<Mutex<Option<String>>>,
}

#[tonic::async_trait]
impl LockServiceServerTrait for TokenRecordingLockServer {
    async fn lock(&self, request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        let resources = request.into_inner().resources;
        self.seen_lock_tokens.lock().unwrap().extend(
            resources
                .iter()
                .map(|resource| resource.expected_ownership_token.clone()),
        );
        Ok(Response::new(LockResponse {
            locks: resources
                .into_iter()
                .map(|resource| WireLock {
                    resource: Some(resource),
                    owner: "wp120-test-owner".to_string(),
                    ownership_token: Bytes::copy_from_slice(&MINTED_TOKEN),
                    locked_at: None,
                })
                .collect(),
        }))
    }

    async fn query(
        &self,
        _request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
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
        let resources = request.into_inner().resources;
        self.seen_unlock_tokens.lock().unwrap().extend(
            resources
                .iter()
                .map(|resource| resource.expected_ownership_token.clone()),
        );
        Ok(Response::new(UnlockResponse { resources }))
    }

    async fn admin_lock(
        &self,
        _request: Request<AdminLockRequest>,
    ) -> Result<Response<AdminLockResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn force_unlock(
        &self,
        request: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        let request = request.into_inner();
        *self.seen_force_unlock_owner.lock().unwrap() = Some(request.owner);
        Ok(Response::new(ForceUnlockResponse {
            resources: request.resources,
        }))
    }
}

#[allow(clippy::type_complexity)]
async fn start_token_recording_server() -> (
    lock_client::LockService,
    Arc<Mutex<Vec<Bytes>>>,
    Arc<Mutex<Vec<Bytes>>>,
    Arc<Mutex<Option<String>>>,
) {
    let seen_lock_tokens = Arc::new(Mutex::new(Vec::new()));
    let seen_unlock_tokens = Arc::new(Mutex::new(Vec::new()));
    let seen_force_unlock_owner = Arc::new(Mutex::new(None));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = TokenRecordingLockServer {
        seen_lock_tokens: seen_lock_tokens.clone(),
        seen_unlock_tokens: seen_unlock_tokens.clone(),
        seen_force_unlock_owner: seen_force_unlock_owner.clone(),
    };

    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LockServiceServer::new(server))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .expect("connect to test server");
    let channel = ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(channel);
    let auth: GRPCAuthRef = Arc::new(parking_lot::RwLock::new(GRPCAuth {
        authorization_token: "test-lore-jwt".to_string(),
        ..Default::default()
    }));
    let client = lock_client::LockService::new(channel, RepositoryId::from([0x01u8; 16]), auth);
    (
        client,
        seen_lock_tokens,
        seen_unlock_tokens,
        seen_force_unlock_owner,
    )
}

/// `Lock` over a fenced cell returns the exact token the server minted, surfaced on
/// `AcquiredLock` -- not silently dropped the way a bare `LockData` conversion would drop it.
#[tokio::test]
async fn lock_surfaces_the_servers_minted_ownership_token() {
    let (client, ..) = start_token_recording_server().await;
    let resources = vec![FencedLockResource::tokenless(one_resource())];

    let acquired = client
        .lock(&resources, None)
        .await
        .expect("lock must succeed");

    assert_eq!(acquired.len(), 1);
    let token = acquired[0]
        .ownership_token
        .as_ref()
        .expect("a fenced Lock response must carry a real token");
    assert_eq!(token.as_bytes().as_ref(), &MINTED_TOKEN[..]);
}

/// A first acquire holds no token yet, and the client must still send the request: a
/// tokenless `FencedLockResource` must reach the wire with an empty
/// `expected_ownership_token`, not be silently dropped from the batch.
#[tokio::test]
async fn lock_sends_no_token_for_a_tokenless_resource() {
    let (client, seen_lock_tokens, ..) = start_token_recording_server().await;
    let resources = vec![FencedLockResource::tokenless(one_resource())];

    client
        .lock(&resources, None)
        .await
        .expect("lock must succeed");

    assert_eq!(seen_lock_tokens.lock().unwrap().clone(), vec![Bytes::new()]);
}

/// `Unlock` presents the caller's stored ownership on the wire, byte for byte.
#[tokio::test]
async fn unlock_presents_the_stored_ownership_token_on_the_wire() {
    let (client, _lock_tokens, seen_unlock_tokens, _owner) = start_token_recording_server().await;
    let token = OwnershipToken::from_wire(&MINTED_TOKEN)
        .expect("valid width")
        .expect("32 bytes must decode to Some");
    let resources = vec![FencedLockResource::with_token(one_resource(), Some(token))];

    client
        .unlock(&resources)
        .await
        .expect("unlock must succeed");

    assert_eq!(
        seen_unlock_tokens.lock().unwrap().clone(),
        vec![Bytes::copy_from_slice(&MINTED_TOKEN)]
    );
}

/// `Unlock` still sends a tokenless resource rather than withholding it: an unfenced cell
/// issues no tokens at all, and a client that filtered these out could release nothing there.
#[tokio::test]
async fn unlock_still_sends_a_tokenless_resource() {
    let (client, _lock_tokens, seen_unlock_tokens, _owner) = start_token_recording_server().await;
    let resources = vec![FencedLockResource::tokenless(one_resource())];

    let released = client
        .unlock(&resources)
        .await
        .expect("unlock must succeed");

    assert_eq!(
        released.len(),
        1,
        "a tokenless resource must still be sent and released"
    );
    assert_eq!(
        seen_unlock_tokens.lock().unwrap().clone(),
        vec![Bytes::new()]
    );
}

/// `ForceUnlock` names the owner being released and needs no token of its own: the
/// administrator holds none, and the RPC's whole point is releasing someone else's lock.
#[tokio::test]
async fn force_unlock_names_the_owner_and_needs_no_token() {
    let (client, _lock_tokens, _unlock_tokens, seen_owner) = start_token_recording_server().await;
    let resources = vec![one_resource()];

    let released = client
        .force_unlock(&resources, "wp120-force-unlock-target")
        .await
        .expect("force_unlock must succeed");

    assert_eq!(released.len(), 1);
    assert_eq!(
        seen_owner.lock().unwrap().clone(),
        Some("wp120-force-unlock-target".to_string())
    );
}
