// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): a live `UrcAuthApi.CheckUserPermission` stub plus
//! an HS256 verifier and token minter, for tests that drive the real
//! `AuthClientAuthorizer` over the network. Used to pin the fork write gate on
//! the HTTP and QUIC surfaces: an identity token (no `resources` claim) may
//! read after the auth service answers, but a write still needs `write` in the
//! token's own claim, whatever the auth service grants.

use std::collections::HashMap;
use std::convert::Infallible;
use std::ops::Add;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::encode;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwk::JWKService;
use lore_server::auth::jwk::JWKServiceError;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::JwtVerifier;
use lore_server::auth::jwt::ResourcePermission;
use tonic::codegen::*;

const SECRET: &str = "auth-client-fixture-secret";
const AUDIENCE: &str = "lore-test";
const ISSUER: &str = "auth-client-fixture-issuer";

struct HsKey;

#[async_trait::async_trait]
impl JWKService for HsKey {
    async fn get_key(&self, _: &str) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
        Ok((DecodingKey::from_secret(SECRET.as_ref()), Algorithm::HS256))
    }

    fn get_cached_key(&self, _: &str) -> Option<(DecodingKey, Algorithm)> {
        Some((DecodingKey::from_secret(SECRET.as_ref()), Algorithm::HS256))
    }

    async fn refresh_key(
        &self,
        _: &str,
    ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
        Ok(None)
    }
}

pub(crate) fn verifier() -> JwtVerifier {
    JwtVerifier {
        jwk_service: Arc::new(HsKey),
        jwt_issuer: Some(vec![ISSUER.to_string()]),
        jwt_audience: Some(vec![AUDIENCE.to_string()]),
        jwt_typ: None,
        identity_claim: "sub".to_string(),
    }
}

pub(crate) fn urc(repository: RepositoryId) -> String {
    format!("urc-{repository}")
}

/// Mints a token the [`verifier`] accepts. `resources: None` is an identity
/// token: it carries no `resources` claim, so `AuthClient` asks the stub.
pub(crate) fn token(resources: Option<Vec<(String, Vec<&str>)>>) -> String {
    let claims = AuthorizationToken {
        user_id: "alice".to_string(),
        issuer: ISSUER.to_string(),
        issued_at: 1,
        audience: vec![AUDIENCE.to_string()],
        expires: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .add(Duration::from_secs(600))
            .as_secs(),
        resources: resources.map(|entries| {
            entries
                .into_iter()
                .map(|(resource_id, permission)| ResourcePermission {
                    resource_id,
                    permission: permission.into_iter().map(str::to_string).collect(),
                })
                .collect()
        }),
        ..Default::default()
    };
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k".to_string());
    encode(&header, &claims, &EncodingKey::from_secret(SECRET.as_ref())).unwrap()
}

#[derive(Clone)]
struct StubAuth {
    table: Arc<HashMap<String, Vec<String>>>,
    calls: Arc<AtomicUsize>,
}

impl tonic::server::NamedService for StubAuth {
    const NAME: &'static str = "epic_urc.UrcAuthApi";
}

struct CheckUserPermission(Arc<HashMap<String, Vec<String>>>);

impl tonic::server::UnaryService<lore_proto::auth::CheckUserPermissionRequest>
    for CheckUserPermission
{
    type Response = lore_proto::auth::CheckUserPermissionResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(
        &mut self,
        request: tonic::Request<lore_proto::auth::CheckUserPermissionRequest>,
    ) -> Self::Future {
        let table = self.0.clone();
        Box::pin(async move {
            let resource_id = request
                .into_inner()
                .resource_id
                .into_iter()
                .next()
                .unwrap_or_default();
            match table.get(&resource_id) {
                Some(permission) => Ok(tonic::Response::new(
                    lore_proto::auth::CheckUserPermissionResponse {
                        allowed_resource_permission: vec![lore_proto::auth::ResourcePermission {
                            resource_id,
                            permission: permission.clone(),
                        }],
                        denied_resource_permission: vec![],
                    },
                )),
                None => Err(tonic::Status::permission_denied("stub: no grant")),
            }
        })
    }
}

impl<B> Service<http::Request<B>> for StubAuth
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        assert_eq!(
            request.uri().path(),
            "/epic_urc.UrcAuthApi/CheckUserPermission"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        let method = CheckUserPermission(self.table.clone());
        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
        Box::pin(async move { Ok(grpc.unary(method, request).await) })
    }
}

/// Serves `CheckUserPermission` on an ephemeral port, answering each resource
/// in `grants` with its permissions and refusing every other one. Returns the
/// `auth_url` and a counter of calls the stub answered.
pub(crate) async fn start_stub(grants: Vec<(String, Vec<&str>)>) -> (String, Arc<AtomicUsize>) {
    let table: HashMap<String, Vec<String>> = grants
        .into_iter()
        .map(|(resource, permission)| {
            (
                resource,
                permission.into_iter().map(str::to_string).collect(),
            )
        })
        .collect();
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = StubAuth {
        table: Arc::new(table),
        calls: calls.clone(),
    };
    lore_base::lore_spawn!(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });
    (format!("http://{address}"), calls)
}
