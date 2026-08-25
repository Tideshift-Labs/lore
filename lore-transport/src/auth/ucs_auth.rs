// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use async_trait::async_trait;
use lore_base::types::RepositoryId;
use lore_proto::auth::ExchangeExternalTokenForUserTokenRequest;
use lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest;
use lore_proto::auth::GetAuthSessionRequest;
use lore_proto::auth::GetUserIdRequest;
use lore_proto::auth::GetUserInfoRequest;
use lore_proto::auth::RefreshAuthSessionRequest;
use lore_proto::auth::StartAuthSessionRequest;
use lore_proto::auth::urc_auth_api_client::UrcAuthApiClient;
use tonic::transport::ClientTlsConfig;

use crate::error::ProtocolError;
use crate::grpc::CorrelationInterceptor;
use crate::traits::Authentication;
use crate::types::*;

/// Strips the custom scheme from an auth URL and returns an HTTPS URL
/// suitable for gRPC connection.
///
/// `ucs-auth://auth.example.com` -> `https://auth.example.com`
/// `https://auth.example.com` -> `https://auth.example.com` (unchanged)
fn grpc_endpoint(auth_url: &str) -> String {
    match auth_url.split_once("://") {
        Some(("https", _)) => auth_url.to_string(),
        Some((_, rest)) => format!("https://{rest}"),
        None => format!("https://{auth_url}"),
    }
}

/// Formats a `RepositoryId` as a UCS Auth resource identifier.
fn resource_id(repository: RepositoryId) -> String {
    format!("urc-{repository}")
}

/// Creates a gRPC client with correlation ID interceptor, connected to the
/// auth endpoint.
async fn connect_client(
    auth_url: &str,
) -> Result<
    UrcAuthApiClient<
        tonic::codegen::InterceptedService<tonic::transport::Channel, CorrelationInterceptor>,
    >,
    ProtocolError,
> {
    let endpoint = grpc_endpoint(auth_url);
    let mut endpoint_config = tonic::transport::Endpoint::new(endpoint.clone())
        .map_err(|e| ProtocolError::internal(format!("invalid auth endpoint: {e}")))?;
    // Trust the OS/native root store for TLS, matching the data channel
    // (`grpc::connect_to_endpoint`) and loreserver's own auth client
    // (`lore-server/src/authnz/auth.rs`). Without this, tonic establishes no
    // TLS for an `https://` endpoint and the exchange handshake fails.
    if endpoint.starts_with("https://") {
        endpoint_config = endpoint_config
            .tls_config(
                ClientTlsConfig::new()
                    .assume_http2(true)
                    .with_native_roots(),
            )
            .map_err(|e| ProtocolError::internal(format!("auth endpoint TLS config: {e}")))?;
    }
    // Connect from a net-runtime task so the channel's driver tasks are
    // bound to the net runtime.
    let channel = lore_base::lore_spawn_net!(async move { endpoint_config.connect().await })
        .await
        .map_err(|e| ProtocolError::internal(format!("auth endpoint connect task: {e}")))?
        .map_err(|e| ProtocolError::internal(format!("failed to connect to auth endpoint: {e}")))?;
    Ok(UrcAuthApiClient::with_interceptor(
        channel,
        CorrelationInterceptor,
    ))
}

/// Sets the authorization header on a gRPC request.
fn set_auth_header<T>(request: &mut tonic::Request<T>, token: &str) -> Result<(), ProtocolError> {
    let mut header: tonic::metadata::MetadataValue<_> = format!("Bearer {token}")
        .parse()
        .map_err(|e| ProtocolError::internal(format!("invalid metadata value: {e}")))?;
    header.set_sensitive(true);
    request.metadata_mut().append("authorization", header);
    Ok(())
}

/// Convert the UCS wire envelope into the provider-neutral transport type.
fn authentication_token(token: lore_proto::auth::UserToken) -> AuthenticationToken {
    AuthenticationToken {
        token: token.user_token,
        user_id: token.user_id,
        user_name: token.user_name,
        expires_ms: token.expires_at.max(0) as u64,
        // Populated by the orchestration layer via JWT decode, not the proto response.
        acceptable_root_domains: Vec::new(),
        refresh_token: token.refresh_token.filter(|value| !value.is_empty()),
    }
}

fn required_authentication_token(
    token: Option<lore_proto::auth::UserToken>,
    operation: &str,
) -> Result<AuthenticationToken, ProtocolError> {
    token
        .map(authentication_token)
        .ok_or_else(|| ProtocolError::internal(format!("empty user token in {operation} response")))
}

/// Authentication implementation using UCS Auth API gRPC service.
///
/// Registered under the `ucs-auth` scheme (and `https` during transition).
/// All `lore_proto::auth` imports are confined to this module.
///
/// The `correlation_id` parameter on trait methods is not used directly --
/// correlation IDs are injected into gRPC requests by `CorrelationInterceptor`,
/// which reads from the ambient context. Non-gRPC implementations
/// would use the parameter instead.
#[derive(Default)]
pub struct UcsAuthentication;

#[async_trait]
impl Authentication for UcsAuthentication {
    async fn start_auth_session(
        &self,
        auth_url: &str,
        client_state: &str,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        let mut client = connect_client(auth_url).await?;

        let request = StartAuthSessionRequest {
            client_state: client_state.to_string(),
        };
        let res = client
            .start_auth_session(request)
            .await
            .map_err(ProtocolError::from)?;

        let inner = res.into_inner();
        Ok(AuthSession {
            session_code: inner.session_code,
            login_url: inner.login_url,
        })
    }

    async fn poll_auth_session(
        &self,
        auth_url: &str,
        client_state: &str,
        session_code: &str,
        _correlation_id: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        let mut client = connect_client(auth_url).await?;

        let request = GetAuthSessionRequest {
            client_state: client_state.to_string(),
            session_code: session_code.to_string(),
        };
        let res = client
            .get_auth_session(request)
            .await
            .map_err(ProtocolError::from)?;

        Ok(res.into_inner().user_token.map(authentication_token))
    }

    async fn exchange_external_token(
        &self,
        auth_url: &str,
        token: &str,
        token_type: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let mut client = connect_client(auth_url).await?;

        let request = ExchangeExternalTokenForUserTokenRequest {
            external_token: token.to_string(),
            token_type: token_type.to_string(),
        };
        let res = client
            .exchange_external_token_for_user_token(request)
            .await
            .map_err(ProtocolError::from)?;

        required_authentication_token(res.into_inner().user_token, "exchange")
    }

    async fn refresh_authentication(
        &self,
        auth_url: &str,
        refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let mut client = connect_client(auth_url).await?;

        let mut request = tonic::Request::new(RefreshAuthSessionRequest {});
        set_auth_header(&mut request, refresh_token)?;
        let res = client
            .refresh_auth_session(request)
            .await
            .map_err(ProtocolError::from)?;

        required_authentication_token(res.into_inner().user_token, "refresh")
    }

    async fn exchange_for_repository(
        &self,
        auth_url: &str,
        authn_token: &str,
        repository: RepositoryId,
        correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        self.exchange_for_custom_resource(
            auth_url,
            authn_token,
            &resource_id(repository),
            correlation_id,
        )
        .await
    }

    async fn exchange_for_custom_resource(
        &self,
        auth_url: &str,
        authn_token: &str,
        resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        let mut client = connect_client(auth_url).await?;

        let mut request = tonic::Request::new(ExchangeUserTokenForMultiresourceTokenRequest {
            resource_id: vec![resource_id.to_string()],
        });
        set_auth_header(&mut request, authn_token)?;

        let res = client
            .exchange_user_token_for_multiresource_token(request)
            .await
            .map_err(ProtocolError::from)?;

        let token = res
            .into_inner()
            .token
            .ok_or_else(|| ProtocolError::internal("empty token in exchange response"))?;

        Ok(AuthorizationToken {
            token: token.user_token,
            expires_ms: token.expires_at.max(0) as u64,
            // Populated by orchestration layer via JWT decode, not the proto response
            acceptable_root_domains: Vec::new(),
        })
    }

    async fn get_user_info(
        &self,
        auth_url: &str,
        authz_token: &str,
        repository: RepositoryId,
        user_ids: &[String],
        _correlation_id: &str,
    ) -> Result<Vec<ResolvedUser>, ProtocolError> {
        let mut client = connect_client(auth_url).await?;

        let mut request = tonic::Request::new(GetUserInfoRequest {
            resource_id: resource_id(repository),
            user_id: user_ids.to_vec(),
        });
        set_auth_header(&mut request, authz_token)?;

        let res = client
            .get_user_info(request)
            .await
            .map_err(ProtocolError::from)?;

        Ok(res
            .into_inner()
            .user_info
            .into_iter()
            .map(|u| ResolvedUser {
                user_id: u.user_id,
                user_name: u.display_name,
            })
            .collect())
    }

    async fn get_user_id(
        &self,
        auth_url: &str,
        authz_token: &str,
        repository: RepositoryId,
        display_name: &str,
        _correlation_id: &str,
    ) -> Result<Option<ResolvedUser>, ProtocolError> {
        let mut client = connect_client(auth_url).await?;

        let mut request = tonic::Request::new(GetUserIdRequest {
            resource_id: resource_id(repository),
            user_display_name: display_name.to_string(),
        });
        set_auth_header(&mut request, authz_token)?;

        let res = client
            .get_user_id(request)
            .await
            .map_err(ProtocolError::from)?;

        Ok(res.into_inner().user_info.map(|u| ResolvedUser {
            user_id: u.user_id,
            user_name: u.display_name,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future::Ready;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::Context;
    use std::task::Poll;

    use lore_proto::auth::UserToken;

    use super::*;

    #[derive(Clone, Default)]
    struct CaptureGrpcPath {
        path: Arc<Mutex<Option<String>>>,
    }

    impl tower::Service<http::Request<tonic::body::Body>> for CaptureGrpcPath {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
            *self.path.lock().expect("path lock") = Some(request.uri().path().to_string());
            std::future::ready(Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .header("content-type", "application/grpc")
                .header("grpc-status", tonic::Code::Unimplemented as i32)
                .body(tonic::body::Body::empty())
                .expect("valid gRPC response")))
        }
    }

    fn wire_user_token(refresh_token: Option<&str>) -> UserToken {
        UserToken {
            user_token: "authn-token".to_string(),
            expires_at: 1_234,
            user_id: "user-1".to_string(),
            user_name: "User One".to_string(),
            refresh_token: refresh_token.map(str::to_string),
        }
    }

    #[test]
    fn grpc_endpoint_ucs_auth() {
        assert_eq!(
            grpc_endpoint("ucs-auth://auth.example.com"),
            "https://auth.example.com"
        );
    }

    #[test]
    fn grpc_endpoint_https() {
        assert_eq!(
            grpc_endpoint("https://auth.example.com"),
            "https://auth.example.com"
        );
    }

    #[test]
    fn grpc_endpoint_no_scheme() {
        assert_eq!(
            grpc_endpoint("auth.example.com"),
            "https://auth.example.com"
        );
    }

    #[test]
    fn grpc_endpoint_custom_scheme() {
        assert_eq!(
            grpc_endpoint("custom://auth.example.com:8443/path"),
            "https://auth.example.com:8443/path"
        );
    }

    #[test]
    fn resource_id_format() {
        let repo_id = RepositoryId::default();
        let rid = resource_id(repo_id);
        assert!(rid.starts_with("urc-"));
        // Default RepositoryId is all zeros, displayed as hex
        assert_eq!(rid, "urc-00000000000000000000000000000000");
    }

    #[test]
    fn authentication_token_maps_refresh_credential() {
        let token = authentication_token(wire_user_token(Some("refresh-1")));

        assert_eq!(token.refresh_token.as_deref(), Some("refresh-1"));
    }

    #[test]
    fn authentication_token_preserves_absent_refresh_credential() {
        let token = authentication_token(wire_user_token(None));

        assert!(token.refresh_token.is_none());
    }

    #[test]
    fn authentication_token_treats_empty_refresh_credential_as_absent() {
        let token = authentication_token(wire_user_token(Some("")));

        assert!(token.refresh_token.is_none());
    }

    #[test]
    fn authentication_token_maps_identity_and_expiry() {
        let token = authentication_token(wire_user_token(Some("refresh-1")));

        assert_eq!(
            (
                token.token.as_str(),
                token.user_id.as_str(),
                token.user_name.as_str(),
                token.expires_ms,
            ),
            ("authn-token", "user-1", "User One", 1_234)
        );
    }

    #[test]
    fn authentication_token_clamps_negative_expiry_to_zero() {
        let mut wire = wire_user_token(None);
        wire.expires_at = -1;

        assert_eq!(authentication_token(wire).expires_ms, 0);
    }

    #[test]
    fn refresh_request_is_empty_and_bearer_is_sensitive() {
        let mut request = tonic::Request::new(RefreshAuthSessionRequest {});

        set_auth_header(&mut request, "opaque refresh").expect("valid metadata");

        let header = request
            .metadata()
            .get("authorization")
            .expect("authorization header");
        assert_eq!(
            header.to_str().expect("ASCII header"),
            "Bearer opaque refresh"
        );
        assert!(header.is_sensitive());
        assert_eq!(request.into_inner(), RefreshAuthSessionRequest {});
    }

    #[tokio::test]
    async fn generated_refresh_client_uses_exact_rpc_path() {
        let service = CaptureGrpcPath::default();
        let path = Arc::clone(&service.path);
        let mut client = UrcAuthApiClient::new(service);

        let error = client
            .refresh_auth_session(RefreshAuthSessionRequest {})
            .await
            .expect_err("stub returns unimplemented");

        assert_eq!(error.code(), tonic::Code::Unimplemented);
        assert_eq!(
            path.lock().expect("path lock").as_deref(),
            Some("/epic_urc.UrcAuthApi/RefreshAuthSession")
        );
    }

    #[test]
    fn required_authentication_token_reports_empty_exchange_response() {
        let error = required_authentication_token(None, "exchange")
            .expect_err("missing exchange token must fail");

        assert!(
            error
                .to_string()
                .contains("empty user token in exchange response")
        );
    }

    #[test]
    fn required_authentication_token_reports_empty_refresh_response() {
        let error = required_authentication_token(None, "refresh")
            .expect_err("missing refresh token must fail");

        assert!(
            error
                .to_string()
                .contains("empty user token in refresh response")
        );
    }
}
