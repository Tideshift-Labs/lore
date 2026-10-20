// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::time::Duration;

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
use crate::traits::UserService;
use crate::types::*;

/// The auth URL schemes [`UcsAuthentication`] is registered under, for
/// authentication and the user service alike. `https` is the transition
/// fallback. `http` serves local test auth services; The implementation only
/// honours plaintext for loopback hosts and upgrades any other http URL to
/// https (see [`grpc_endpoint`]).
pub const SCHEMES: [&str; 3] = ["ucs-auth", "https", "http"];

/// Strips the custom scheme from an auth URL and returns a URL suitable for
/// gRPC connection.
///
/// `ucs-auth://auth.example.com` -> `https://auth.example.com`
/// `https://auth.example.com` -> `https://auth.example.com` (unchanged)
/// `http://127.0.0.1:41339` -> `http://127.0.0.1:41339` (unchanged)
/// `http://auth.example.com` -> `https://auth.example.com` (upgraded)
///
/// Plaintext `http` is honoured only for loopback hosts, where the traffic
/// never leaves the machine — this lets a local test auth service run
/// without a certificate. For any other host the scheme is upgraded to
/// `https`: the auth URL arrives in the *remote server's* advertised
/// environment config, so allowing http to an arbitrary host would let a rogue
/// server downgrade the channel that carries login and exchange tokens.
pub fn grpc_endpoint(auth_url: &str) -> String {
    match auth_url.split_once("://") {
        Some(("https", _)) => auth_url.to_string(),
        Some(("http", _))
            if url::Url::parse(auth_url).is_ok_and(|url| super::is_loopback_http_url(&url)) =>
        {
            auth_url.to_string()
        }
        Some((_, rest)) => format!("https://{rest}"),
        None => format!("https://{auth_url}"),
    }
}

/// Formats a `RepositoryId` as a UCS Auth resource identifier.
#[lore_macro::test_pub]
fn resource_id(repository: RepositoryId) -> String {
    format!("urc-{repository}")
}

/// Bounds on the auth channel. Without them an auth endpoint that accepts and never answers
/// blocks its caller forever, and a session rebind holds its lock across that wait.
const AUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const AUTH_RPC_TIMEOUT: Duration = Duration::from_secs(30);
const AUTH_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const AUTH_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

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
        .map_err(|e| ProtocolError::internal(format!("invalid auth endpoint: {e}")))?
        .connect_timeout(AUTH_CONNECT_TIMEOUT)
        .timeout(AUTH_RPC_TIMEOUT)
        .http2_keep_alive_interval(AUTH_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(AUTH_KEEP_ALIVE_TIMEOUT);
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
#[lore_macro::test_pub]
fn set_auth_header<T>(request: &mut tonic::Request<T>, token: &str) -> Result<(), ProtocolError> {
    let mut header: tonic::metadata::MetadataValue<_> = format!("Bearer {token}")
        .parse()
        .map_err(|e| ProtocolError::internal(format!("invalid metadata value: {e}")))?;
    header.set_sensitive(true);
    request.metadata_mut().append("authorization", header);
    Ok(())
}

/// Convert the UCS wire envelope into the provider-neutral transport type.
#[lore_macro::test_pub]
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

#[lore_macro::test_pub]
fn required_authentication_token(
    token: Option<lore_proto::auth::UserToken>,
    operation: &str,
) -> Result<AuthenticationToken, ProtocolError> {
    token
        .map(authentication_token)
        .ok_or_else(|| ProtocolError::internal(format!("empty user token in {operation} response")))
}

/// Authentication and user service over the UCS Auth API gRPC service.
///
/// Registered under [`SCHEMES`] in both registries. All `lore_proto::auth`
/// imports are confined to this module.
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
}

#[async_trait]
impl UserService for UcsAuthentication {
    async fn get_user_info(
        &self,
        user_url: &str,
        authz_token: &str,
        repository: RepositoryId,
        user_ids: &[String],
        _correlation_id: &str,
    ) -> Result<Vec<ResolvedUser>, ProtocolError> {
        let mut client = connect_client(user_url).await?;

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
        user_url: &str,
        authz_token: &str,
        repository: RepositoryId,
        display_name: &str,
        _correlation_id: &str,
    ) -> Result<Option<ResolvedUser>, ProtocolError> {
        let mut client = connect_client(user_url).await?;

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
