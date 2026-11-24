// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_base::error::AddressNotFound;
use lore_base::error::Disconnected;
use lore_base::error::Maintenance;
use lore_base::error::NoRemote;
use lore_base::error::NotAuthenticated;
use lore_base::error::NotAuthorized;
use lore_base::error::NotFound;
use lore_base::error::NotSupported;
use lore_base::error::OutcomeUnknown;
use lore_base::error::Oversized;
use lore_base::error::SlowDown;
use lore_base::lore_debug;
use lore_base::lore_spawn_guarded;
use lore_base::lore_trace;
use lore_base::lore_warn;
use lore_base::types::RepositoryId;
use lore_credential::get_domain_or_empty;
use lore_credential::insecure_decode_token;
use lore_credential::token_store;
use lore_credential::token_store::Refreshed;
use lore_credential::token_store::tokens_only_for_recipient_domain;
use lore_credential::unsigned_identity_token;
use lore_credential::verify_jwt_usage_for_remote;
use lore_error_set::prelude::*;
use tokio::sync::Mutex;

use crate::auth::AuthEndpoint;
use crate::connection::CredentialStore;
use crate::connection::credential_store;

#[error_set]
pub enum ExchangeError {
    NotAuthenticated,
    NotAuthorized,
    Disconnected,
    SlowDown,
    Maintenance,
    NotFound,
    AddressNotFound,
    NoRemote,
    NotSupported,
    Oversized,
    /// Declared so an unknown outcome forwarded from `ProtocolError` survives this hop
    /// rather than being collapsed (WP-120). The exchange itself never produces one.
    OutcomeUnknown,
}

type AuthEndpointUrl = String;
type Identity = String;
type CacheResourceId = String;
type RecipientDomain = String;
type CredentialFingerprint = String;
#[lore_macro::test_pub]
type AuthzKey = (
    AuthEndpointUrl,
    Identity,
    CacheResourceId,
    RecipientDomain,
    CredentialFingerprint,
    CredentialStore,
);

/// A key's flight lock and the number of callers waiting on or holding it.
type Flight = (Arc<Mutex<()>>, usize);

/// The in-memory authorization cache.
///
/// `tokens` is held only for one map read or write, never across an await.
/// A miss runs its exchange under that key's own flight lock in `flights`, so
/// concurrent misses on one key share a single exchange while misses on
/// different keys run in parallel. `flights` holds a key only while a lookup
/// for it is in progress, with the number of callers waiting on or holding it.
///
/// `epoch` is held shared for the whole of a lookup and exclusively by
/// [`clear_authz_cache`]. A clear therefore waits out every exchange already
/// running, as it did when one lock guarded everything, and none of them can
/// put an entry back after it returns.
#[lore_macro::test_pub]
struct AuthzCache {
    epoch: tokio::sync::RwLock<()>,
    tokens: parking_lot::Mutex<HashMap<AuthzKey, String>>,
    flights: parking_lot::Mutex<HashMap<AuthzKey, Flight>>,
}

static AUTHZ_CACHE: std::sync::OnceLock<AuthzCache> = std::sync::OnceLock::new();

/// One caller's share of a key's flight lock.
///
/// Dropping it, whether its caller finished, failed, or was cancelled while
/// waiting or exchanging, releases the share. The last share removes the key
/// from `flights`, so no outcome leaves a key wedged or the map growing.
struct FlightTicket {
    key: AuthzKey,
    flight: Arc<Mutex<()>>,
}

impl FlightTicket {
    fn join(key: &AuthzKey) -> Self {
        let mut flights = cache().flights.lock();
        let entry = flights
            .entry(key.clone())
            .or_insert_with(|| (Arc::new(Mutex::new(())), 0));
        entry.1 += 1;
        Self {
            key: key.clone(),
            flight: entry.0.clone(),
        }
    }
}

impl Drop for FlightTicket {
    fn drop(&mut self) {
        let mut flights = cache().flights.lock();
        let last = match flights.get_mut(&self.key) {
            Some(entry) if Arc::ptr_eq(&entry.0, &self.flight) => {
                entry.1 = entry.1.saturating_sub(1);
                entry.1 == 0
            }
            _ => false,
        };
        if last {
            flights.remove(&self.key);
        }
    }
}

/// What an exchange authorizes against.
#[derive(Clone, Copy)]
enum AuthzResource<'a> {
    Repository(RepositoryId),
    Custom(&'a str),
}

/// Refresh authentication five minutes before expiry so the existing
/// once-per-minute auth loop has multiple retry opportunities.
pub const AUTHENTICATION_REFRESH_LEAD_MS: u64 = 5 * 60 * 1_000;
const AUTHENTICATION_REFRESH_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHENTICATION_REFRESH_PROVIDER_TIMEOUT: Duration = Duration::from_secs(15);

#[lore_macro::test_pub]
#[derive(Clone, Copy)]
struct AuthenticationRefreshTimeouts {
    lock: Duration,
    provider: Duration,
}

const AUTHENTICATION_REFRESH_TIMEOUTS: AuthenticationRefreshTimeouts =
    AuthenticationRefreshTimeouts {
        lock: AUTHENTICATION_REFRESH_LOCK_TIMEOUT,
        provider: AUTHENTICATION_REFRESH_PROVIDER_TIMEOUT,
    };

#[lore_macro::test_pub]
fn cache() -> &'static AuthzCache {
    AUTHZ_CACHE.get_or_init(|| AuthzCache {
        epoch: tokio::sync::RwLock::new(()),
        tokens: parking_lot::Mutex::new(HashMap::new()),
        flights: parking_lot::Mutex::new(HashMap::new()),
    })
}

/// Evicts every exchanged authorization token from the in-memory cache.
/// Entries are keyed per `(auth_url, identity, resource, recipient_domain)`
/// and otherwise live until process exit — a credential reset (sign-out) must
/// drop them so a later session cannot reuse the previous identity's tokens.
/// Called from `connection::drop_connections()` as part of the full transport
/// reset.
pub async fn clear_authz_cache() {
    if let Some(cache) = AUTHZ_CACHE.get() {
        let _epoch = cache.epoch.write().await;
        cache.tokens.lock().clear();
    }
}

/// The key an authorization for `resource` is cached under: the endpoint, the identity, the
/// resource, the recipient domain, the fingerprint of the identity token the caller supplied,
/// empty for credentials from the token store, and the token store the call reads.
fn authorization_cache_key(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    resource: &str,
    recipient_domain: &str,
    identity_token: &str,
) -> AuthzKey {
    (
        auth_endpoint.url.clone(),
        identity.to_string(),
        resource.to_string(),
        recipient_domain.to_string(),
        lore_credential::token_fingerprint(identity_token),
        credential_store(),
    )
}

/// The key an authorization for `resource` is stored under in the token store.
#[lore_macro::test_pub]
fn authorization_store_key(auth_endpoint: &AuthEndpoint, resource: &str) -> String {
    format!("{auth_endpoint}/{resource}")
}

/// Forgets `refused`, an authorization for `repository` that [`exchange`] handed out and the
/// server has since refused, so the next exchange does not serve `refused` until it expires.
///
/// It is forgotten from the cache and, unless the caller supplied the identity token, from the
/// token store, which the exchange reads on a cache miss. The cache stays locked until both are
/// done, so no exchange reads `refused` back from the store meanwhile. An entry holding another
/// token is left alone, as another caller has replaced it already. The store's entry is compared
/// as [`token_store::remove_user_token_if`] compares it, so one another process has stored is
/// left alone too.
#[lore_macro::test_pub]
pub(crate) async fn forget_refused_authorization(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    repository: RepositoryId,
    recipient_domain: &str,
    identity_token: &str,
    refused: &str,
) {
    let repository = repository.to_string();
    let cache_key = authorization_cache_key(
        auth_endpoint,
        identity,
        &repository,
        recipient_domain,
        identity_token,
    );
    // FORK-LOCAL (Tideshift): the fork's cache is per-key single-flight (see [AuthzCache]), so
    // holding the key's flight lock is what keeps an exchange for this key from reading `refused`
    // back from the store meanwhile. Never hold the map lock across the store removal.
    let authz = cache();
    let _epoch = authz.epoch.read().await;
    let ticket = FlightTicket::join(&cache_key);
    let _flight = ticket.flight.lock().await;
    {
        let mut tokens = authz.tokens.lock();
        if tokens.get(&cache_key).is_some_and(|token| token == refused) {
            tokens.remove(&cache_key);
        }
    }
    if identity_token.is_empty() {
        let token_store_key = authorization_store_key(auth_endpoint, &repository);
        let _ = token_store::remove_user_token_if(&token_store_key, identity, refused)
            .await
            .inspect_err(|err| lore_warn!("Failed to remove a refused authorization: {err}"));
    }
}

pub fn is_expired(expires: u64) -> bool {
    let current_time = current_time_ms();
    current_time >= expires
}

#[lore_macro::test_pub]
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Pure refresh-window decision, exposed for boundary tests.
pub fn authentication_refresh_due(expires_ms: u64, now_ms: u64) -> bool {
    expires_ms <= now_ms.saturating_add(AUTHENTICATION_REFRESH_LEAD_MS)
}

fn token_is_unexpired(token: &str, now_ms: u64) -> bool {
    lore_credential::user_info_from_token(token.to_string())
        .is_none_or(|info| info.expires > now_ms)
}

/// `identity`'s authentication token to send to `remote_domain` once a refresh has run or been
/// given up on: the one stored for that domain if it is unexpired, which is the refreshed token
/// or one another caller stored meanwhile, else `current_token` if it is unexpired, else empty.
///
/// The stored token is read for `remote_domain`, so it is sent only where the issuer named in
/// it allows. `current_token` came through the same filter before the refresh started.
async fn usable_authentication_token(
    auth_url: &str,
    identity: &str,
    remote_domain: &str,
    current_token: &str,
) -> String {
    let now_ms = current_time_ms();
    let stored = token_store::load_user_token_from_store(
        auth_url,
        identity,
        tokens_only_for_recipient_domain(remote_domain.to_string()),
    )
    .await
    .ok()
    .filter(|token| token_is_unexpired(token, now_ms));
    if let Some(stored) = stored {
        return stored;
    }
    if token_is_unexpired(current_token, now_ms) {
        return current_token.to_string();
    }
    lore_debug!("Skipping identity {identity}, no unexpired authn token for {remote_domain}");
    String::new()
}

/// Refresh an authentication token when its JWT expiry enters the lead window. The auth URL is
/// resolved through the scheme registry; see [`refresh_authentication_if_due`].
#[lore_macro::test_pub]
async fn refresh_authentication_if_needed(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    current_token: String,
) -> String {
    refresh_authentication_if_needed_with_timeouts(
        auth_url,
        remote_domain,
        identity,
        current_token,
        AUTHENTICATION_REFRESH_TIMEOUTS,
    )
    .await
}

#[lore_macro::test_pub]
async fn refresh_authentication_if_needed_with_timeouts(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    current_token: String,
    timeouts: AuthenticationRefreshTimeouts,
) -> String {
    match AuthEndpoint::resolve(auth_url) {
        Ok(auth_endpoint) => {
            refresh_authentication_if_due(
                &auth_endpoint,
                remote_domain,
                identity,
                current_token,
                timeouts,
            )
            .await
        }
        Err(err) => {
            lore_debug!(
                "No authentication implementation to refresh {identity} at {auth_url}: {err}"
            );
            usable_authentication_token(auth_url, identity, remote_domain, &current_token).await
        }
    }
}

/// `current_token`, `identity`'s authentication token from the store, or the token that
/// replaces it when its expiry is within [`AUTHENTICATION_REFRESH_LEAD_MS`]: one obtained with
/// the stored refresh token, or one another caller has stored meanwhile. Empty when it has
/// expired and nothing replaces it.
///
/// Upstream's refresh grant (one-time-use refresh tokens, `Disconnected` only when unsent) runs
/// under the fork's CR-020 refresh lease ([`token_store::AuthenticationRefreshLease`]), so one
/// process at a time presents a refresh token, and a process that waited finds the winner's
/// token without a second grant. The fork also refreshes ahead of expiry, and bounds how long a
/// caller waits: for the lease by `timeouts.lock`, then for the grant by `timeouts.provider`.
///
/// The refresh runs in a guarded task, so neither a caller that gives up, such as a connection
/// being cancelled or a timeout above, nor the process shutting down stops it part way, which
/// would lose the refresh token the issuer has consumed. A caller that stops waiting uses the
/// still valid token, or the one the task has stored by then.
async fn refresh_authentication_if_due(
    auth_endpoint: &AuthEndpoint,
    remote_domain: &str,
    identity: &str,
    current_token: String,
    timeouts: AuthenticationRefreshTimeouts,
) -> String {
    let Some(current_info) = lore_credential::user_info_from_token(current_token.clone()) else {
        // Preserve the historical behavior for opaque/non-JWT credentials.
        return current_token;
    };
    if !authentication_refresh_due(current_info.expires, current_time_ms()) {
        return current_token;
    }

    let (answer, refreshed) = tokio::sync::oneshot::channel();
    let endpoint = auth_endpoint.clone();
    let user = identity.to_owned();
    let presented = current_token.clone();
    let lock_timeout = timeouts.lock;
    lore_spawn_guarded!(async move {
        let lease = tokio::time::timeout(
            lock_timeout,
            token_store::acquire_authentication_refresh(&endpoint.url, &user),
        )
        .await;
        let refreshed = match lease {
            Ok(Ok(lease)) => {
                lease
                    .refresh(&presented, |refresh_token| {
                        let endpoint = &endpoint;
                        async move {
                            // As for the exchange, no correlation ID is available at this layer.
                            match endpoint
                                .auth
                                .refresh_authentication(&endpoint.url, &refresh_token, "")
                                .await
                            {
                                Ok(authn) => Refreshed::Token {
                                    token: authn.token,
                                    refresh_token: authn.refresh_token,
                                    refresh_expires: authn.refresh_expires_ms,
                                    scope: authn.scope,
                                },
                                Err(err) if err.is_not_authenticated() => Refreshed::Refused(err),
                                Err(err) if err.is_disconnected() => Refreshed::Unsent(err),
                                Err(err) => Refreshed::Failed(err),
                            }
                        }
                    })
                    .await
            }
            Ok(Err(err)) => Err(err),
            Err(_) => Err(token_store::TokenStoreError::internal(
                "Timed out waiting for the authentication refresh lease",
            )),
        };
        let _ = answer.send(refreshed);
    });

    match tokio::time::timeout(timeouts.lock.saturating_add(timeouts.provider), refreshed).await {
        Ok(Ok(Ok(_))) => {}
        Ok(Ok(Err(err))) if err.is_token_not_found() => {
            lore_debug!("No refresh token to refresh {identity} with");
        }
        Ok(Ok(Err(err))) => {
            lore_debug!("Authentication refresh failed for {identity}: {err}");
        }
        Ok(Err(_)) => {
            lore_warn!("The token refresh task ended without an answer");
        }
        Err(_) => {
            lore_debug!("Authentication refresh timed out for {identity}");
        }
    }
    usable_authentication_token(&auth_endpoint.url, identity, remote_domain, &current_token).await
}

/// The login token to trade at `auth_endpoint` for `identity`: `identity_token` when supplied,
/// else the stored one, refreshed if it is due. `None` when there is none that is usable.
async fn login_token_for_auth_service(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    identity_token: &str,
) -> Option<String> {
    if !identity_token.is_empty() {
        return lore_credential::user_info_from_token(identity_token.to_owned())
            .map(|info| info.token);
    }
    let auth_domain = get_domain_or_empty(&auth_endpoint.url);
    let token = token_store::load_user_token_from_store(
        &auth_endpoint.url,
        identity,
        tokens_only_for_recipient_domain(auth_domain.clone()),
    )
    .await
    .ok()?;
    let token = refresh_authentication_if_due(
        auth_endpoint,
        &auth_domain,
        identity,
        token,
        AUTHENTICATION_REFRESH_TIMEOUTS,
    )
    .await;
    (!token.is_empty()).then_some(token)
}

/// Exchanges an authentication token for a repository-scoped authorization
/// token via the registered `Authentication` implementation.
///
/// Checks the in-memory cache and on-disk token store first. On miss,
/// loads the authn token and delegates to the implementation's
/// `exchange_for_repository`. The returned authz token is cached in memory
/// and persisted to the token store. If the caller supplies external
/// `identity_token` or `access_token`, the exchanged token is not persisted
/// to on-disk store to keep tokens related to external identities out of
/// the store. Also the on-disk store is not read in this case to not mix the
/// external tokens with cached login tokens. The in-memory cache keeps them
/// apart too: an entry is keyed by the credential that earned it, so a supplied
/// token is never served an authorization that another credential produced, and
/// by the token store the call reads, so a call is never served an authorization
/// another caller's store produced.
///
/// Token store keys use `"{auth_endpoint.url}/{repository_id}"` (no implementation-
/// specific prefix). The `Authentication` implementation handles resource ID
/// formatting internally.
///
/// A non-empty `identity_token` replaces the authentication token.
///
/// A non-empty `access_token` the authorization token.
pub async fn exchange(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    repository: RepositoryId,
    recipient_domain: String,
    identity_token: &str,
    access_token: &str,
) -> Result<String, ExchangeError> {
    if !access_token.is_empty() {
        lore_debug!("Using the supplied access token for repository {repository}");
        return Ok(access_token.to_string());
    }
    if auth_endpoint.is_none() {
        lore_debug!("No auth url, unable to perform authz exchange");
        return Err(NotSupported {
            operation: "No authentication configured on server".to_string(),
        }
        .into());
    }
    if identity.is_empty() {
        lore_debug!("No identity, unable to perform authz exchange");
        return Err(NotAuthenticated::new(format!(
            "no identity is configured for repository {repository}; sign in first"
        ))
        .into());
    }

    cached_authorization(
        auth_endpoint,
        identity,
        AuthzResource::Repository(repository),
        recipient_domain,
        identity_token,
    )
    .await
}

/// Exchanges an authentication token for an authorization token scoped to an
/// arbitrary resource identifier (non-repository). Mirrors `exchange` but
/// delegates to the implementation's `exchange_for_custom_resources`, letting
/// callers authorize against resources the `RepositoryId` model cannot express.
///
/// The `resource_id` is used verbatim as the cache/token-store key and is
/// passed unmodified to the auth backend.
///
/// `identity_token` and `access_token` are the caller-supplied credentials.
pub async fn exchange_custom_resource(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    resource_id: &str,
    recipient_domain: String,
    identity_token: &str,
    access_token: &str,
) -> Result<String, ExchangeError> {
    if !access_token.is_empty() {
        lore_debug!("Using the supplied access token for resource {resource_id}");
        return Ok(access_token.to_string());
    }
    if auth_endpoint.is_none() {
        lore_debug!("No auth url, unable to perform authz exchange");
        return Err(NotSupported {
            operation: "No authentication configured on server".to_string(),
        }
        .into());
    }
    if identity.is_empty() {
        lore_debug!("No identity, unable to perform authz exchange");
        return Err(NotAuthenticated::new(format!(
            "no identity is configured for resource {resource_id}; sign in first"
        ))
        .into());
    }
    if resource_id.is_empty() {
        lore_debug!("No resource_id, unable to perform authz exchange");
        return Err(ExchangeError::internal(
            "Failed to exchange token: empty resource_id",
        ));
    }

    cached_authorization(
        auth_endpoint,
        identity,
        AuthzResource::Custom(resource_id),
        recipient_domain,
        identity_token,
    )
    .await
}

/// True when `token` decodes and has not expired.
fn authorization_is_current(token: &str) -> bool {
    lore_credential::user_info_from_token(token.to_string())
        .is_some_and(|user_info| !is_expired(user_info.expires))
}

/// The cache, token-store and exchange steps shared by [`exchange`] and
/// [`exchange_custom_resource`], once their argument checks have passed and a
/// supplied access token has returned.
///
/// A current in-memory entry is served without waiting on anything but the
/// map. Otherwise the caller joins the key's flight and repeats the lookup
/// under it: a caller that waited behind a successful exchange finds that
/// exchange's token, and one that waited behind a failed or cancelled one
/// finds nothing and runs its own.
async fn cached_authorization(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    resource: AuthzResource<'_>,
    recipient_domain: String,
    identity_token: &str,
) -> Result<String, ExchangeError> {
    let resource_id = match resource {
        AuthzResource::Repository(repository) => repository.to_string(),
        AuthzResource::Custom(resource_id) => resource_id.to_string(),
    };
    // A supplied access token returned before this, so the identity token is
    // the only credential that reaches the cache or the store from here.
    let supplied_credentials = !identity_token.is_empty();
    // Token store key: "{auth_endpoint.url}/{resource_id}" (no urc- prefix). A custom
    // resource ID takes the repository slot.
    let token_store_key = authorization_store_key(auth_endpoint, &resource_id);
    let cache_key = authorization_cache_key(
        auth_endpoint,
        identity,
        &resource_id,
        &recipient_domain,
        identity_token,
    );
    let authz = cache();
    let _epoch = authz.epoch.read().await;

    let cached = authz.tokens.lock().get(&cache_key).cloned();
    if let Some(token) = cached
        && authorization_is_current(&token)
    {
        lore_trace!("Using cached authz token for {cache_key:?}");
        return Ok(token);
    }

    // Declared before the guard, so the guard is released before the ticket.
    let ticket = FlightTicket::join(&cache_key);
    let _flight = ticket.flight.lock().await;

    let cached = authz.tokens.lock().get(&cache_key).cloned();
    lore_trace!("Check for cached authz token for {cache_key:?}");
    let mut token = cached.unwrap_or_default();

    if !token.is_empty() {
        lore_trace!("Found cached authz token for {cache_key:?}");
    } else if !supplied_credentials {
        lore_trace!("Check for token store authz token for {token_store_key:?}");
        token = token_store::load_user_token_from_store(
            &token_store_key,
            identity,
            tokens_only_for_recipient_domain(recipient_domain.clone()),
        )
        .await
        .unwrap_or_default();
    }

    if !token.is_empty() {
        lore_trace!("Validating token expiry");
        if let Some(user_info) = lore_credential::user_info_from_token(token.clone()) {
            if !is_expired(user_info.expires) {
                lore_trace!("Using authz token for {cache_key:?}");
                authz.tokens.lock().insert(cache_key, token.clone());
                return Ok(token);
            } else {
                lore_debug!("Authz token for {cache_key:?} has expired");
            }
        } else {
            lore_warn!("Invalid authz token found for {cache_key:?}");
        }
    } else {
        lore_trace!("No stored authz token found for {cache_key:?}");
    }

    let (token, acceptable_root_domains) = exchange_fresh(
        auth_endpoint,
        identity,
        resource,
        &recipient_domain,
        identity_token,
    )
    .await?;

    lore_trace!("Cached authz token for {cache_key:?}");
    authz.tokens.lock().insert(cache_key, token.clone());

    if !supplied_credentials {
        let _ = token_store::store_user_token(
            &token_store_key,
            identity,
            &token,
            acceptable_root_domains,
        )
        .await
        .map_err(|err| {
            lore_warn!("Failed to store token: {err}");
        });
    }

    Ok(token)
}

/// Loads the authentication token, runs the exchange with the registered
/// `Authentication` implementation and checks the result. Returns the
/// authorization token and the root domains it may be sent to.
async fn exchange_fresh(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    resource: AuthzResource<'_>,
    recipient_domain: &str,
    identity_token: &str,
) -> Result<(String, Vec<String>), ExchangeError> {
    // Load authn token for the auth service domain
    lore_trace!("Authorizing using authn identity: {identity}");
    let auth_url = auth_endpoint.url.as_str();
    let Some(auth_service_only_token) =
        login_token_for_auth_service(auth_endpoint, identity, identity_token).await
    else {
        lore_debug!("Not authenticated, unable to perform authz exchange");
        return Err(NotAuthenticated::new(format!(
            "no usable authentication token is stored for identity {identity} at {auth_url}; sign in again"
        ))
        .into());
    };
    lore_trace!("Authorizing using endpoint: {auth_endpoint}");

    let time_start = Instant::now();

    // Delegate to the Authentication implementation
    let auth_impl = &auth_endpoint.auth;
    // The correlation_id is no longer available from ExecutionContext in lore-transport.
    // Pass an empty string -- the gRPC interceptor may inject it from ambient state.
    let correlation_id = String::new();

    lore_trace!("Send auth exchange request");
    let authz = match resource {
        AuthzResource::Repository(repository) => {
            auth_impl
                .exchange_for_repository(
                    auth_url,
                    &auth_service_only_token,
                    repository,
                    &correlation_id,
                )
                .await
        }
        AuthzResource::Custom(resource_id) => {
            auth_impl
                .exchange_for_custom_resources(
                    auth_url,
                    &auth_service_only_token,
                    &[resource_id],
                    &correlation_id,
                )
                .await
        }
    }
    .map_err(|err| {
        // Kept by class so a caller can tell an unreachable or throttled auth
        // service, or a session that needs signing in again, from a fault.
        // Everything else, including a `NotFound`, stays `Internal`: an auth
        // service answer must never read as a missing repository.
        if err.is_not_authorized() {
            ExchangeError::from(NotAuthorized)
        } else if err.is_disconnected() {
            ExchangeError::from(Disconnected)
        } else if err.is_slow_down() {
            ExchangeError::from(SlowDown)
        } else if err.is_not_authenticated() {
            ExchangeError::from(NotAuthenticated::new(format!(
                "Failed to exchange token: {err}"
            )))
        } else {
            ExchangeError::internal_with_context(err, "Failed to exchange token")
        }
    })?;

    let token = authz.token;
    if token.is_empty() {
        return Err(ExchangeError::internal("Empty token response"));
    }
    let decoded_token = insecure_decode_token(&token)
        .internal("Could not decode token")
        .map_err(ExchangeError::from)?;
    verify_jwt_usage_for_remote(&decoded_token.claims, recipient_domain).map_err(|err| {
        lore_warn!("{err}");
        ExchangeError::internal_with_context(
            err,
            "The token is not suitable for what you intend to do",
        )
    })?;

    lore_trace!(
        "Authorization with user token successful in {} ms",
        time_start.elapsed().as_millis()
    );

    Ok((token, decoded_token.claims.acceptable_root_domains()))
}

/// The authentication and authorization tokens, and the identity, for a server that
/// advertises no authentication: one unsigned token naming `identity` in both slots. A server
/// with `server.trust_unsigned_identity` records the caller under that identity, and any
/// other server without authentication ignores it. `None` when there is an auth endpoint, no
/// identity, or a supplied credential, which then takes the usual path.
pub(crate) fn unsigned_identity_tokens(
    auth_endpoint: &AuthEndpoint,
    identity: &str,
    identity_token: &str,
    access_token: &str,
) -> Option<(String, String, String)> {
    if !auth_endpoint.is_none()
        || identity.is_empty()
        || !identity_token.is_empty()
        || !access_token.is_empty()
    {
        return None;
    }
    let token = unsigned_identity_token(identity)
        .inspect_err(|err| lore_warn!("Could not encode an unsigned identity token: {err}"))
        .ok()?;
    Some((token.clone(), token, identity.to_string()))
}

/// Resolves an identity and obtains authentication/authorization tokens.
///
/// Returned tuple: (`authentication_token`, `authorization_token`, `resolved_identity`)
///
/// If `identity` is empty, iterates over available identities for the given
/// `auth_endpoint` and tries to find one that can authenticate (and optionally
/// authorize for the given repository).
///
/// `identity_token` and `access_token` are the caller-supplied credentials.
pub async fn auth_exchange(
    auth_endpoint: &AuthEndpoint,
    remote_domain: &str,
    identity: &str,
    repository: RepositoryId,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    if let Some(tokens) =
        unsigned_identity_tokens(auth_endpoint, identity, identity_token, access_token)
    {
        return tokens;
    }

    if !identity.is_empty() {
        return auth_exchange_for_identity(
            auth_endpoint,
            remote_domain,
            identity,
            repository,
            identity_token,
            access_token,
        )
        .await;
    }

    // No identity given, resolve one from available identities
    let Ok(identities) = token_store::load_identities(&auth_endpoint.url).await else {
        lore_debug!("No identities found for {auth_endpoint}");
        return (String::new(), String::new(), String::new());
    };

    if repository.is_zero() {
        // No resource, pick first identity with a valid authn token
        for entry in &identities {
            let result =
                auth_exchange_for_identity(auth_endpoint, remote_domain, entry, repository, "", "")
                    .await;
            if !result.0.is_empty() {
                return result;
            }
        }
        return (String::new(), String::new(), String::new());
    }

    // Try each identity: first check for cached/stored authz token, then try exchange
    for entry in &identities {
        let result =
            auth_exchange_for_identity(auth_endpoint, remote_domain, entry, repository, "", "")
                .await;
        if !result.1.is_empty() {
            return result;
        }
    }

    lore_debug!("No identity could be authorized for repository {repository}");
    (String::new(), String::new(), String::new())
}

#[lore_macro::test_pub]
async fn auth_exchange_for_identity(
    auth_endpoint: &AuthEndpoint,
    remote_domain: &str,
    identity: &str,
    repository: RepositoryId,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    let authentication_token = token_store::load_user_token(
        &auth_endpoint.url,
        identity,
        tokens_only_for_recipient_domain(remote_domain.to_string()),
        identity_token,
        access_token,
    )
    .await
    .unwrap_or_default();

    // A supplied access token authorizes on its own, so carry on without an
    // authentication token: the services that need one fail where they use it,
    // and the ones that only need authorization still work.
    if authentication_token.is_empty() && access_token.is_empty() {
        lore_debug!("Auth exchange failed, no user authentication token found for {identity}");
        return (String::new(), String::new(), String::new());
    }

    // Refresh only a credential resolved from the store. A credential supplied
    // by the caller is an instruction, not a refresh candidate, even when it is
    // expired; the server must reject that exact credential so the caller sees
    // an authentication failure rather than an anonymous request.
    let authentication_token = if identity_token.is_empty() && access_token.is_empty() {
        refresh_authentication_if_due(
            auth_endpoint,
            remote_domain,
            identity,
            authentication_token,
            AUTHENTICATION_REFRESH_TIMEOUTS,
        )
        .await
    } else {
        authentication_token
    };
    if identity_token.is_empty() && access_token.is_empty() && authentication_token.is_empty() {
        lore_debug!("Skipping identity {identity}, authn token is expired");
        return (String::new(), String::new(), String::new());
    }

    // This will return the cached authz token if it is still valid,
    // or perform an authz exchange if needed
    let authorization_token = if !repository.is_zero() {
        exchange(
            auth_endpoint,
            identity,
            repository,
            remote_domain.to_string(),
            identity_token,
            access_token,
        )
        .await
        .inspect_err(|err| {
            lore_debug!("Auth exchange failed for repository {repository}: {err}");
        })
        .unwrap_or_default()
    } else {
        String::new()
    };

    // Dedupe these debug lines: the same identity getting reselected for the
    // same repository/domain pair on every authz refresh is the steady-state
    // and just spams the log. Re-emit only when the inputs change. The lock
    // is dropped before we log so the dispatch (file write, event channel)
    // cannot block other callers.
    if !authorization_token.is_empty() {
        static LAST_AUTHORIZED: parking_lot::Mutex<Option<(String, RepositoryId, String)>> =
            parking_lot::Mutex::new(None);
        let key = (identity.to_string(), repository, remote_domain.to_string());
        let changed = {
            let mut last = LAST_AUTHORIZED.lock();
            if last.as_ref() != Some(&key) {
                *last = Some(key);
                true
            } else {
                false
            }
        };
        if changed {
            lore_debug!(
                "Selected identity {identity}, authorized for repository {repository} on {remote_domain}"
            );
        }
    } else if repository.is_zero() {
        static LAST_AUTHENTICATED: parking_lot::Mutex<Option<(String, String)>> =
            parking_lot::Mutex::new(None);
        let key = (identity.to_string(), remote_domain.to_string());
        let changed = {
            let mut last = LAST_AUTHENTICATED.lock();
            if last.as_ref() != Some(&key) {
                *last = Some(key);
                true
            } else {
                false
            }
        };
        if changed {
            lore_debug!("Selected identity {identity}, authenticated for {remote_domain}");
        }
    }

    (
        authentication_token,
        authorization_token,
        identity.to_string(),
    )
}

/// Resolves an identity and obtains authentication/authorization tokens for an
/// arbitrary resource identifier.
///
/// Returned tuple: (`authentication_token`, `authorization_token`, `resolved_identity`)
///
/// Mirrors `auth_exchange`, but authorizes against a caller-supplied resource
/// identifier rather than a repository.
pub async fn auth_exchange_custom_resource(
    auth_endpoint: &AuthEndpoint,
    remote_domain: &str,
    identity: &str,
    resource_id: &str,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    if let Some(tokens) =
        unsigned_identity_tokens(auth_endpoint, identity, identity_token, access_token)
    {
        return tokens;
    }

    if !identity.is_empty() {
        return auth_exchange_custom_resource_for_identity(
            auth_endpoint,
            remote_domain,
            identity,
            resource_id,
            identity_token,
            access_token,
        )
        .await;
    }

    let Ok(identities) = token_store::load_identities(&auth_endpoint.url).await else {
        lore_debug!("No identities found for {auth_endpoint}");
        return (String::new(), String::new(), String::new());
    };

    // Store-resolved identities use store credentials, pass empty tokens.
    for entry in &identities {
        let result = auth_exchange_custom_resource_for_identity(
            auth_endpoint,
            remote_domain,
            entry,
            resource_id,
            "",
            "",
        )
        .await;
        if !result.1.is_empty() {
            return result;
        }
    }

    lore_debug!("No identity could be authorized for resource {resource_id}");
    (String::new(), String::new(), String::new())
}

#[lore_macro::test_pub]
async fn auth_exchange_custom_resource_for_identity(
    auth_endpoint: &AuthEndpoint,
    remote_domain: &str,
    identity: &str,
    resource_id: &str,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    let authentication_token = token_store::load_user_token(
        &auth_endpoint.url,
        identity,
        tokens_only_for_recipient_domain(remote_domain.to_string()),
        identity_token,
        access_token,
    )
    .await
    .unwrap_or_default();

    // A supplied access token authorizes on its own, so carry on without an
    // authentication token: the services that need one fail where they use it,
    // and the ones that only need authorization still work.
    if authentication_token.is_empty() && access_token.is_empty() {
        lore_debug!("Auth exchange failed, no user authentication token found for {identity}");
        return (String::new(), String::new(), String::new());
    }

    // As in `auth_exchange_for_identity`, refresh only store-resolved
    // credentials and hand caller-supplied credentials over unchanged.
    let authentication_token = if identity_token.is_empty() && access_token.is_empty() {
        refresh_authentication_if_due(
            auth_endpoint,
            remote_domain,
            identity,
            authentication_token,
            AUTHENTICATION_REFRESH_TIMEOUTS,
        )
        .await
    } else {
        authentication_token
    };
    if identity_token.is_empty() && access_token.is_empty() && authentication_token.is_empty() {
        lore_debug!("Skipping identity {identity}, authn token is expired");
        return (String::new(), String::new(), String::new());
    }

    let authorization_token = exchange_custom_resource(
        auth_endpoint,
        identity,
        resource_id,
        remote_domain.to_string(),
        identity_token,
        access_token,
    )
    .await
    .inspect_err(|err| {
        lore_debug!("Auth exchange failed for resource {resource_id}: {err}");
    })
    .unwrap_or_default();

    // Dedupe: same identity reselected for the same resource/domain on every
    // refresh is the steady-state — re-emit only when the inputs change.
    // Drop the lock before logging so dispatch can't block other callers.
    if !authorization_token.is_empty() {
        static LAST_RESOURCE_AUTHORIZED: parking_lot::Mutex<Option<(String, String, String)>> =
            parking_lot::Mutex::new(None);
        let key = (
            identity.to_string(),
            resource_id.to_string(),
            remote_domain.to_string(),
        );
        let changed = {
            let mut last = LAST_RESOURCE_AUTHORIZED.lock();
            if last.as_ref() != Some(&key) {
                *last = Some(key);
                true
            } else {
                false
            }
        };
        if changed {
            lore_debug!(
                "Selected identity {identity}, authorized for resource {resource_id} on {remote_domain}"
            );
        }
    }

    (
        authentication_token,
        authorization_token,
        identity.to_string(),
    )
}
