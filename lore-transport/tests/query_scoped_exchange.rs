// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! `Repository::query_scoped` end to end over the REAL `exchange()`, with a REAL non-empty
//! `auth_url`.
//!
//! [CLIENT]-class (`lore-transport`). Companion to `authn_bearer_carriage.rs`, which can only
//! reach the supplied-token short circuit (empty `auth_url`), and to
//! `tests/unit/grpc/repository_scoped_get.rs` / `tests/unit/auth/exchange.rs`, which test the
//! policy and the exchange separately. This file joins them through the public
//! [`lore_transport::connect`] seam against a fake loreserver:
//!
//! - `EnvironmentService` advertises an `auth_url` whose scheme is served by a stub
//!   [`Authentication`] registered in the process-global `authentication` registry;
//! - `RepositoryService` records the `authorization` header of every by-id `RepositoryGet`.
//!
//! # Isolation
//!
//! The authentication registry and `AUTHZ_CACHE` are process-global and this binary runs its
//! tests in parallel, so every test uses its own scheme, its own identity and its own
//! repository ids, and clears the cache entries of its identity first. Nothing touches the token
//! store: a supplied `identity_token` short-circuits `load_user_token`.
//!
//! # Connect repository id
//!
//! Every connection is made with `RepositoryId::default()` (zero). A non-zero id would trigger
//! the connect-time exchange (`connection.rs`, `if !repository.is_zero()`) against the stub, which
//! would add an exchange call per test and, for the failing policies, fail the whole connection
//! before `query_scoped` runs. The repositories under test are the ids passed to
//! `query_scoped`, not the one the connection was made with.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use lore_base::error::Disconnected;
use lore_base::error::NotAuthorized;
use lore_base::error::NotFound;
use lore_base::types::RepositoryId;
use lore_proto::lore::environment::v1 as environment_v1;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentService as EnvironmentServiceV1;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentServiceServer;
use lore_proto::lore::repository::v1 as repository_v1;
use lore_proto::lore::repository::v1::repository_service_server::RepositoryService as RepositoryServiceV1;
use lore_proto::lore::repository::v1::repository_service_server::RepositoryServiceServer;
use lore_transport::auth::authentication;
use lore_transport::auth::exchange::cache;
use lore_transport::error::ProtocolError;
use lore_transport::traits::Authentication;
use lore_transport::types::AuthSession;
use lore_transport::types::AuthenticationToken;
use lore_transport::types::AuthorizationToken;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;

type ResponseStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send>>;

// ---------------------------------------------------------------------------------------
// Token helpers: unsigned JWTs, the shape `exchange()` decodes and domain-checks.
// ---------------------------------------------------------------------------------------

fn base64_url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::new();
    for chunk in input.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(ALPHABET[((bits >> 18) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((bits >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[((bits >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(bits & 0x3f) as usize] as char);
        }
    }
    encoded
}

/// A far-future (year 2100) unsigned JWT for `subject`, valid for the loopback recipient the
/// fake server listens on.
fn jwt(subject: &str) -> String {
    let header = base64_url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = format!(
        r#"{{"iss":"auth.example.com","sub":"{subject}","name":"Test User","exp":4102444800,"aud":["127.0.0.1","localhost"]}}"#
    );
    format!("{header}.{}.", base64_url(payload.as_bytes()))
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// Lowercase hex, the form `RepositoryId`'s `Display` uses.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn repo(tag: u8) -> RepositoryId {
    RepositoryId::from([tag; 16])
}

// ---------------------------------------------------------------------------------------
// Stub Authentication: only `exchange_for_repository` is live, and it branches on the id.
// ---------------------------------------------------------------------------------------

type ExchangePolicy =
    dyn Fn(RepositoryId) -> Result<AuthorizationToken, ProtocolError> + Send + Sync;

struct StubAuthentication {
    policy: Box<ExchangePolicy>,
    exchanges: AtomicUsize,
}

fn granted(token: &str) -> Result<AuthorizationToken, ProtocolError> {
    Ok(AuthorizationToken {
        token: token.to_string(),
        expires_ms: u64::MAX,
        acceptable_root_domains: Vec::new(),
    })
}

#[async_trait]
impl Authentication for StubAuthentication {
    async fn start_auth_session(
        &self,
        _auth_url: &str,
        _client_state: &str,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn poll_auth_session(
        &self,
        _auth_url: &str,
        _client_state: &str,
        _session_code: &str,
        _correlation_id: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn exchange_external_token(
        &self,
        _auth_url: &str,
        _token: &str,
        _token_type: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn refresh_authentication(
        &self,
        _auth_url: &str,
        _refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn exchange_for_repository(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        (self.policy)(repository)
    }

    async fn exchange_for_custom_resource(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }
}

// ---------------------------------------------------------------------------------------
// Fake loreserver: EnvironmentService + a recording RepositoryService.
// ---------------------------------------------------------------------------------------

struct Environment {
    auth_url: String,
}

#[tonic::async_trait]
impl EnvironmentServiceV1 for Environment {
    async fn environment_get(
        &self,
        _request: Request<environment_v1::EnvironmentGetRequest>,
    ) -> Result<Response<environment_v1::EnvironmentGetResponse>, Status> {
        Ok(Response::new(environment_v1::EnvironmentGetResponse {
            environment: Some(environment_v1::Environment {
                endpoint: Some(environment_v1::Endpoint {
                    auth_url: self.auth_url.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }))
    }
}

/// Answers a by-id `RepositoryGet` given the id (hex) and the `authorization` header it carried.
type GetPolicy = dyn Fn(&str, &str) -> Result<(), Status> + Send + Sync;

struct Repository {
    /// `(repository id hex, authorization header)` per by-id `RepositoryGet`, in arrival order.
    gets: Arc<Mutex<Vec<(String, String)>>>,
    policy: Box<GetPolicy>,
}

#[tonic::async_trait]
impl RepositoryServiceV1 for Repository {
    async fn repository_create(
        &self,
        _request: Request<repository_v1::RepositoryCreateRequest>,
    ) -> Result<Response<repository_v1::RepositoryCreateResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn repository_delete(
        &self,
        _request: Request<repository_v1::RepositoryDeleteRequest>,
    ) -> Result<Response<repository_v1::RepositoryDeleteResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn repository_get(
        &self,
        request: Request<repository_v1::RepositoryGetRequest>,
    ) -> Result<Response<repository_v1::RepositoryGetResponse>, Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let Some(repository_v1::repository_get_request::Query::Id(id)) = &request.get_ref().query
        else {
            return Err(Status::invalid_argument("these tests only read by id"));
        };
        let id_hex = hex(id);
        self.gets
            .lock()
            .expect("get log mutex poisoned")
            .push((id_hex.clone(), authorization.clone()));
        (self.policy)(&id_hex, &authorization)?;
        Ok(Response::new(repository_v1::RepositoryGetResponse {
            repository: Some(lore_proto::lore::model::v1::Repository {
                id: id.clone(),
                name: "recorded".to_string(),
                ..Default::default()
            }),
            repository_generation: None,
        }))
    }

    type RepositoryListStream = ResponseStream<repository_v1::RepositoryListResponse>;
    async fn repository_list(
        &self,
        _request: Request<repository_v1::RepositoryListRequest>,
    ) -> Result<Response<Self::RepositoryListStream>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn repository_metadata_get(
        &self,
        _request: Request<repository_v1::RepositoryMetadataGetRequest>,
    ) -> Result<Response<repository_v1::RepositoryMetadataGetResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn repository_metadata_set(
        &self,
        _request: Request<repository_v1::RepositoryMetadataSetRequest>,
    ) -> Result<Response<repository_v1::RepositoryMetadataSetResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn repository_storage_stats(
        &self,
        _request: Request<repository_v1::RepositoryStorageStatsRequest>,
    ) -> Result<Response<repository_v1::RepositoryStorageStatsResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }
}

/// One scenario: a fake server, a registered stub exchanger and a connected repository client.
struct Scenario {
    repository: Arc<dyn lore_transport::traits::Repository>,
    authentication: Arc<StubAuthentication>,
    gets: Arc<Mutex<Vec<(String, String)>>>,
    identity_token: String,
    // Keeps the listener address alive for the scenario's lifetime.
    _addr: SocketAddr,
}

impl Scenario {
    /// `scheme` and `identity` must be unique to the calling test (see the module doc).
    async fn start(
        scheme: &str,
        exchange_policy: impl Fn(RepositoryId) -> Result<AuthorizationToken, ProtocolError>
        + Send
        + Sync
        + 'static,
        get_policy: impl Fn(&str, &str) -> Result<(), Status> + Send + Sync + 'static,
    ) -> Self {
        let identity = format!("qs-identity-{scheme}");
        // Stale entries from an earlier run of this identity cannot exist in a fresh process,
        // but clearing the key is what keeps the test independent of ordering.
        cache().tokens.lock().retain(|key, _| key.1 != identity);

        let stub = Arc::new(StubAuthentication {
            policy: Box::new(exchange_policy),
            exchanges: AtomicUsize::new(0),
        });
        authentication::add(scheme, stub.clone()).expect("register stub authentication");

        let gets: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let environment = Environment {
            auth_url: format!("{scheme}://auth.example.com"),
        };
        let repository_service = Repository {
            gets: gets.clone(),
            policy: Box::new(get_policy),
        };
        lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(EnvironmentServiceServer::new(environment))
                .add_service(RepositoryServiceServer::new(repository_service))
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

        let identity_token = jwt(&identity);
        // Zero repository: see the module doc.
        let connection = lore_transport::connect(
            &format!("grpc://{addr}"),
            &identity,
            RepositoryId::default(),
            1,
            &identity_token,
            "",
        )
        .await
        .expect("connect must succeed against the in-process test server");
        let repository = connection.repository().await.expect("repository client");

        Self {
            repository,
            authentication: stub,
            gets,
            identity_token,
            _addr: addr,
        }
    }

    fn gets_for(&self, id: RepositoryId) -> Vec<String> {
        let wanted = id.to_string();
        self.gets
            .lock()
            .expect("get log mutex poisoned")
            .iter()
            .filter(|(got, _)| *got == wanted)
            .map(|(_, authorization)| authorization.clone())
            .collect()
    }

    fn total_gets(&self) -> usize {
        self.gets.lock().expect("get log mutex poisoned").len()
    }

    fn identity_header(&self) -> String {
        bearer(&self.identity_token)
    }
}

/// Fake-server read policy that answers every request.
fn answer_all(_id: &str, _authorization: &str) -> Result<(), Status> {
    Ok(())
}

// ---------------------------------------------------------------------------------------
// a. An unreachable auth service surfaces as a disconnect; no repository read at all.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_unavailable_auth_exchange_returns_disconnected_with_no_repository_read() {
    let scenario = Scenario::start(
        "qs-unavailable",
        |_| Err(ProtocolError::from(Disconnected)),
        answer_all,
    )
    .await;

    let err = scenario
        .repository
        .query_scoped(repo(0xA1))
        .await
        .expect_err("query_scoped must fail when the auth service is unreachable");

    assert!(err.is_disconnected(), "{err:?}");
    assert!(!err.is_not_found(), "{err:?}");
    assert_eq!(scenario.authentication.exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(
        scenario.total_gets(),
        0,
        "a non-denial must never fall back to a read under another credential"
    );
}

// ---------------------------------------------------------------------------------------
// b. An auth-service NotFound is an internal fault, never a missing repository.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_auth_service_not_found_is_internal_not_a_missing_repository() {
    let scenario = Scenario::start(
        "qs-auth-not-found",
        |_| Err(ProtocolError::from(NotFound)),
        answer_all,
    )
    .await;

    let err = scenario
        .repository
        .query_scoped(repo(0xB1))
        .await
        .expect_err("query_scoped must fail");

    assert!(!err.is_not_found(), "{err:?}");
    assert!(!err.is_not_authorized(), "{err:?}");
    assert!(err.is_internal(), "{err:?}");
    assert_eq!(scenario.total_gets(), 0);
}

// ---------------------------------------------------------------------------------------
// c. A denied exchange falls back to exactly one identity read; the server's answer stands.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_denied_exchange_makes_exactly_one_identity_read_and_the_servers_not_found_stands() {
    let scenario = Scenario::start(
        "qs-denied",
        |_| Err(ProtocolError::from(NotAuthorized)),
        |_, _| Err(Status::not_found("repository does not exist")),
    )
    .await;
    let id = repo(0xC1);

    let err = scenario
        .repository
        .query_scoped(id)
        .await
        .expect_err("the server answers NotFound to the identity read");

    assert!(err.is_not_found(), "{err:?}");
    assert_eq!(
        scenario.gets_for(id),
        vec![scenario.identity_header()],
        "exactly one RepositoryGet, carrying the identity token"
    );
    assert_eq!(scenario.total_gets(), 1);
}

// ---------------------------------------------------------------------------------------
// d. Concurrent repositories: a grant and a denial, plus a plain query, never mix credentials.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_scoped_and_plain_reads_each_carry_their_own_credential() {
    let (a, b, c) = (repo(0xD1), repo(0xD2), repo(0xD3));
    let scoped_a = jwt("scoped-A");
    let granted_a = scoped_a.clone();
    let scenario = Scenario::start(
        "qs-concurrent",
        move |repository| {
            if repository == a {
                granted(&granted_a)
            } else {
                Err(ProtocolError::from(NotAuthorized))
            }
        },
        answer_all,
    )
    .await;

    let (read_a, read_b, read_c) = tokio::join!(
        scenario.repository.query_scoped(a),
        scenario.repository.query_scoped(b),
        scenario.repository.query(Some(c), None),
    );

    assert_eq!(read_a.expect("A is granted").id, a);
    assert_eq!(read_b.expect("B falls back to an identity read").id, b);
    assert_eq!(read_c.expect("plain query").id, c);

    assert_eq!(
        scenario.gets_for(a),
        vec![bearer(&scoped_a)],
        "A reads once, with its scoped token"
    );
    assert_eq!(
        scenario.gets_for(b),
        vec![scenario.identity_header()],
        "B (denied) reads exactly once, with the identity token"
    );
    assert_eq!(
        scenario.gets_for(c),
        vec![scenario.identity_header()],
        "a plain query keeps the identity token"
    );
    assert_eq!(scenario.total_gets(), 3);
    // Both scoped calls exchanged; the plain query never does.
    assert_eq!(scenario.authentication.exchanges.load(Ordering::SeqCst), 2);
}
