// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Owned TLS exchange endpoint; existing ReBAC policy remains a read-only test double.
use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;

use tonic::codegen::*;

pub(super) struct AuthServer {
    pub url: String,
    pub authn: String,
    pub authz: String,
    pub exchanges: Arc<Mutex<Vec<String>>>,
    pub direct_bearers: Arc<Mutex<Vec<String>>>,
    pub permission_checks: Arc<Mutex<Vec<String>>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}
#[derive(Clone)]
struct State {
    upstream: String,
    authn: String,
    authz: String,
    subject: String,
    resource: String,
    expires: i64,
    exchanges: Arc<Mutex<Vec<String>>>,
    direct_bearers: Arc<Mutex<Vec<String>>>,
    permission_checks: Arc<Mutex<Vec<String>>>,
}
fn bearer<T>(request: &tonic::Request<T>) -> &str {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("")
}
impl AuthServer {
    pub async fn start(
        upstream: &str,
        issuer: &str,
        subject: &str,
        repository: &[u8; 16],
        key_path: &std::path::Path,
        port: u16,
    ) -> Self {
        let resource = format!(
            "urc-{}",
            repository
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = now + 3600;
        let key =
            jsonwebtoken::EncodingKey::from_rsa_pem(&std::fs::read(key_path).unwrap()).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("lorehub-test-key-1".into());
        let mut claims = serde_json::json!({"sub":subject,"iss":issuer,"iat":now,"exp":expires,"aud":["commit0-cli","localhost"],"name":"CLI fixture","preferred_username":"CLI fixture","is_service_account":false,"idp":"wp118-cli-test","env":"test","groups":[]});
        let authn = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        claims["aud"] = serde_json::json!(["lore-storage", "localhost"]);
        claims["resources"] =
            serde_json::json!([{"resource_id":resource,"permission":["read","write"]}]);
        let authz = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        assert_ne!(authn, authz);
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let direct_bearers = Arc::new(Mutex::new(Vec::new()));
        let permission_checks = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(State {
            upstream: upstream.into(),
            authn: authn.clone(),
            authz: authz.clone(),
            subject: subject.into(),
            resource,
            expires: (expires * 1000) as i64,
            exchanges: exchanges.clone(),
            direct_bearers: direct_bearers.clone(),
            permission_checks: permission_checks.clone(),
        });
        let identity = tonic::transport::Identity::from_pem(
            std::fs::read(std::env::var("LORE_TEST_CLI_TLS_CERT").unwrap()).unwrap(),
            std::fs::read(std::env::var("LORE_TEST_CLI_TLS_KEY").unwrap()).unwrap(),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        let (shutdown, stop) = tokio::sync::oneshot::channel();
        lore_base::lore_spawn!("cli-auth-tls", async move {
            tonic::transport::Server::builder()
                .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))
                .unwrap()
                .add_service(Urc(state.clone()))
                .add_service(Rebac(state))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stop.await;
                    },
                )
                .await
                .unwrap();
        });
        Self {
            url: format!("https://localhost:{port}"),
            authn,
            authz,
            exchanges,
            direct_bearers,
            permission_checks,
            shutdown: Some(shutdown),
        }
    }
    /// Probe the real owned TLS callback, without broadening identity audiences.
    pub async fn assert_permission_refusals(&self) {
        let ca = tonic::transport::Certificate::from_pem(
            std::fs::read(std::env::var("LORE_TEST_CLEAN_INIT_CA_PATH").unwrap()).unwrap(),
        );
        let channel = tonic::transport::Endpoint::new(self.url.clone())
            .unwrap()
            .tls_config(tonic::transport::ClientTlsConfig::new().ca_certificate(ca))
            .unwrap()
            .connect()
            .await
            .unwrap();
        for (token, expected_code) in [
            (&self.authz, Some(tonic::Code::Unauthenticated)),
            (&self.authn, None),
        ] {
            let mut request = tonic::Request::new(lore_proto::auth::CheckUserPermissionRequest {
                resource_id: vec!["urc-00000000000000000000000000000000".into()],
                target_user: None,
            });
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            let mut grpc = tonic::client::Grpc::new(channel.clone());
            grpc.ready().await.unwrap();
            let result: Result<
                tonic::Response<lore_proto::auth::CheckUserPermissionResponse>,
                tonic::Status,
            > = grpc
                .unary(
                    request,
                    http::uri::PathAndQuery::from_static(
                        "/epic_urc.UrcAuthApi/CheckUserPermission",
                    ),
                    tonic_prost::ProstCodec::default(),
                )
                .await;
            if let Some(code) = expected_code {
                assert_eq!(result.unwrap_err().code(), code);
            } else {
                let response = result.unwrap().into_inner();
                assert!(response.allowed_resource_permission.is_empty());
                assert_eq!(response.denied_resource_permission.len(), 1);
                assert!(response.denied_resource_permission[0].permission.is_empty());
            }
        }
    }
}
impl Drop for AuthServer {
    fn drop(&mut self) {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
    }
}

struct Forward<Q, R> {
    state: Arc<State>,
    path: &'static str,
    marker: PhantomData<(Q, R)>,
}
impl<Q, R> tonic::server::UnaryService<Q> for Forward<Q, R>
where
    Q: prost::Message + Default + Send + Sync + 'static,
    R: prost::Message + Default + Send + Sync + 'static,
{
    type Response = R;
    type Future = BoxFuture<tonic::Response<R>, tonic::Status>;
    fn call(&mut self, request: tonic::Request<Q>) -> Self::Future {
        let state = self.state.clone();
        let path = self.path;
        Box::pin(async move {
            if path.ends_with("AuthorizeDirectRepositoryOperation") {
                let supplied = bearer(&request);
                if supplied != state.authn || supplied == state.authz {
                    return Err(tonic::Status::unauthenticated(
                        "direct operation must carry the identity bearer",
                    ));
                }
                state.direct_bearers.lock().unwrap().push(supplied.into());
            }
            let channel = tonic::transport::Endpoint::new(state.upstream.clone())
                .unwrap()
                .connect()
                .await
                .map_err(|_| tonic::Status::unavailable("owned upstream unavailable"))?;
            let mut grpc = tonic::client::Grpc::new(channel);
            grpc.ready()
                .await
                .map_err(|_| tonic::Status::unavailable("owned upstream not ready"))?;
            grpc.unary(
                request,
                http::uri::PathAndQuery::from_static(path),
                tonic_prost::ProstCodec::default(),
            )
            .await
        })
    }
}
struct Exchange(Arc<State>);
struct Permission(Arc<State>);
impl tonic::server::UnaryService<lore_proto::auth::CheckUserPermissionRequest> for Permission {
    type Response = lore_proto::auth::CheckUserPermissionResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
    fn call(
        &mut self,
        request: tonic::Request<lore_proto::auth::CheckUserPermissionRequest>,
    ) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            if bearer(&request) != state.authn {
                return Err(tonic::Status::unauthenticated("unknown fixture identity"));
            }
            if request.get_ref().target_user.is_some() {
                return Err(tonic::Status::permission_denied(
                    "fixture permits only the authenticated subject",
                ));
            }
            let mut allowed = Vec::new();
            let mut denied = Vec::new();
            for resource_id in request.into_inner().resource_id {
                let granted = resource_id == state.resource;
                if granted {
                    state
                        .permission_checks
                        .lock()
                        .unwrap()
                        .push(resource_id.clone());
                }
                let permission = lore_proto::auth::ResourcePermission {
                    resource_id,
                    permission: if granted {
                        vec!["read".into(), "write".into()]
                    } else {
                        Vec::new()
                    },
                };
                if granted {
                    allowed.push(permission);
                } else {
                    denied.push(permission);
                }
            }
            println!(
                "CLI permission callback: allowed={} denied={}",
                allowed.len(),
                denied.len()
            );
            Ok(tonic::Response::new(
                lore_proto::auth::CheckUserPermissionResponse {
                    allowed_resource_permission: allowed,
                    denied_resource_permission: denied,
                },
            ))
        })
    }
}
impl tonic::server::UnaryService<lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest>
    for Exchange
{
    type Response = lore_proto::auth::ExchangeUserTokenForMultiresourceTokenResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
    fn call(
        &mut self,
        request: tonic::Request<lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            if bearer(&request) != state.authn {
                return Err(tonic::Status::unauthenticated("unknown fixture identity"));
            }
            if request.get_ref().resource_id != [state.resource.clone()] {
                return Err(tonic::Status::permission_denied(
                    "ungranted fixture resource",
                ));
            }
            state.exchanges.lock().unwrap().push(state.resource.clone());
            Ok(tonic::Response::new(
                lore_proto::auth::ExchangeUserTokenForMultiresourceTokenResponse {
                    token: Some(lore_proto::auth::UserToken {
                        user_token: state.authz.clone(),
                        expires_at: state.expires,
                        user_id: state.subject.clone(),
                        user_name: "CLI fixture".into(),
                        refresh_token: None,
                    }),
                },
            ))
        })
    }
}
fn unimplemented() -> http::Response<tonic::body::Body> {
    let mut response = http::Response::new(tonic::body::Body::default());
    response.headers_mut().insert(
        tonic::Status::GRPC_STATUS,
        (tonic::Code::Unimplemented as i32).into(),
    );
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        tonic::metadata::GRPC_CONTENT_TYPE,
    );
    response
}
macro_rules! forward {
    ($self:ident,$req:ident,$request:ty,$response:ty,$path:literal) => {{
        let method = Forward::<$request, $response> {
            state: $self.0.clone(),
            path: $path,
            marker: PhantomData,
        };
        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
        Box::pin(async move { Ok(grpc.unary(method, $req).await) })
    }};
}
#[derive(Clone)]
struct Urc(Arc<State>);
impl tonic::server::NamedService for Urc {
    const NAME: &'static str = "epic_urc.UrcAuthApi";
}
impl<B> Service<http::Request<B>> for Urc
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        match req.uri().path() {
            "/epic_urc.UrcAuthApi/ExchangeUserTokenForMultiresourceToken" => {
                let method = Exchange(self.0.clone());
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Box::pin(async move { Ok(grpc.unary(method, req).await) })
            }
            "/epic_urc.UrcAuthApi/CheckUserPermission" => {
                let method = Permission(self.0.clone());
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Box::pin(async move { Ok(grpc.unary(method, req).await) })
            }
            _ => Box::pin(async { Ok(unimplemented()) }),
        }
    }
}
#[derive(Clone)]
struct Rebac(Arc<State>);
impl tonic::server::NamedService for Rebac {
    const NAME: &'static str = "ucs.auth.RebacApi";
}
impl<B> Service<http::Request<B>> for Rebac
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        match req.uri().path() {
            "/ucs.auth.RebacApi/CreateResource" => forward!(
                self,
                req,
                lore_proto::rebac::CreateResourceRequest,
                lore_proto::rebac::CreateResourceResponse,
                "/ucs.auth.RebacApi/CreateResource"
            ),
            "/ucs.auth.RebacApi/AuthorizeDirectRepositoryOperation" => forward!(
                self,
                req,
                lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest,
                lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse,
                "/ucs.auth.RebacApi/AuthorizeDirectRepositoryOperation"
            ),
            _ => Box::pin(async { Ok(unimplemented()) }),
        }
    }
}
