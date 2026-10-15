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
use lore_base::lore_trace;
use lore_base::lore_warn;
use lore_base::types::RepositoryId;
use lore_credential::get_domain_or_empty;
use lore_credential::insecure_decode_token;
use lore_credential::token_store;
use lore_credential::token_store::AuthenticationRefreshCommit;
use lore_credential::token_store::tokens_only_for_recipient_domain;
use lore_credential::verify_jwt_usage_for_remote;
use lore_error_set::prelude::*;
use tokio::sync::Mutex;

use crate::auth::authentication;

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

type AuthUrl = String;
type Identity = String;
type CacheResourceId = String;
type RecipientDomain = String;
type CredentialFingerprint = String;
#[lore_macro::test_pub]
type AuthzKey = (
    AuthUrl,
    Identity,
    CacheResourceId,
    RecipientDomain,
    CredentialFingerprint,
);

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
    flights: parking_lot::Mutex<HashMap<AuthzKey, (Arc<Mutex<()>>, usize)>>,
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

fn verified_authentication_token(
    token: &str,
    identity: &str,
    remote_domain: &str,
    now_ms: u64,
) -> Option<Vec<String>> {
    let info = lore_credential::user_info_from_token(token.to_string())?;
    if info.id != identity || info.expires <= now_ms {
        lore_warn!("Authentication token has an invalid identity or expiry");
        return None;
    }
    let decoded = insecure_decode_token(token).ok()?;
    if let Err(err) = verify_jwt_usage_for_remote(&decoded.claims, remote_domain) {
        lore_warn!("Authentication token is not suitable for its remote: {err}");
        return None;
    }
    Some(decoded.claims.acceptable_root_domains())
}

fn fallback_authentication_token(
    current_token: &str,
    stored_token: &str,
    identity: &str,
    remote_domain: &str,
    now_ms: u64,
) -> String {
    if verified_authentication_token(stored_token, identity, remote_domain, now_ms).is_some() {
        stored_token.to_string()
    } else if token_is_unexpired(current_token, now_ms) {
        // `current_token` came through the token store's recipient-domain
        // filter before the refresh lease was acquired.
        current_token.to_string()
    } else {
        String::new()
    }
}

/// Refresh an authentication token when its JWT expiry enters the lead window.
///
/// The per-identity token-store lease is acquired before the final decision,
/// then the on-disk pair is re-read. A process that waited for another refresher
/// therefore uses the winner's token without issuing a duplicate request.
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
    let now_ms = current_time_ms();
    let Some(current_info) = lore_credential::user_info_from_token(current_token.clone()) else {
        // Preserve the historical behavior for opaque/non-JWT credentials.
        return current_token;
    };
    if !authentication_refresh_due(current_info.expires, now_ms) {
        return current_token;
    }

    let Ok(Ok(lease)) = tokio::time::timeout(
        timeouts.lock,
        token_store::acquire_authentication_refresh(auth_url, identity),
    )
    .await
    else {
        lore_debug!("Authentication refresh lease timed out or could not be acquired");
        return if token_is_unexpired(&current_token, now_ms) {
            current_token
        } else {
            String::new()
        };
    };

    let stored_token = lease.snapshot().token.clone();
    let Some(stored_info) = lore_credential::user_info_from_token(stored_token.clone()) else {
        lore_warn!("Stored authentication token is invalid while attempting refresh");
        return if token_is_unexpired(&current_token, now_ms) {
            current_token
        } else {
            String::new()
        };
    };
    if stored_info.id != identity {
        lore_warn!("Stored authentication token does not match its identity");
        return if token_is_unexpired(&current_token, now_ms) {
            current_token
        } else {
            String::new()
        };
    }
    if !authentication_refresh_due(stored_info.expires, now_ms) {
        return if verified_authentication_token(&stored_token, identity, remote_domain, now_ms)
            .is_some()
        {
            stored_token
        } else if token_is_unexpired(&current_token, now_ms) {
            current_token
        } else {
            String::new()
        };
    }

    let Ok(auth_impl) = authentication::find(auth_url) else {
        return fallback_authentication_token(
            &current_token,
            &stored_token,
            identity,
            remote_domain,
            now_ms,
        );
    };
    let correlation_id = String::new();
    let refresh_result = tokio::time::timeout(
        timeouts.provider,
        auth_impl.refresh_authentication(
            auth_url,
            lease.snapshot().refresh_token.as_str(),
            &correlation_id,
        ),
    )
    .await;
    let refreshed = match refresh_result {
        Ok(Ok(token)) => token,
        Ok(Err(err)) => {
            lore_debug!("Authentication refresh failed for {identity}: {err}");
            return fallback_authentication_token(
                &current_token,
                &stored_token,
                identity,
                remote_domain,
                now_ms,
            );
        }
        Err(_) => {
            lore_debug!("Authentication refresh timed out for {identity}");
            return fallback_authentication_token(
                &current_token,
                &stored_token,
                identity,
                remote_domain,
                now_ms,
            );
        }
    };

    if refreshed.user_id != identity {
        lore_warn!("Refreshed authentication response changed the user identity");
        return fallback_authentication_token(
            &current_token,
            &stored_token,
            identity,
            remote_domain,
            now_ms,
        );
    }
    let Some(acceptable_root_domains) =
        verified_authentication_token(&refreshed.token, identity, remote_domain, now_ms)
    else {
        return fallback_authentication_token(
            &current_token,
            &stored_token,
            identity,
            remote_domain,
            now_ms,
        );
    };

    let replacement = refreshed.refresh_token.as_deref();
    match lease
        .commit(
            refreshed.token.as_str(),
            replacement,
            acceptable_root_domains,
        )
        .await
    {
        Ok(AuthenticationRefreshCommit::Stored) => refreshed.token,
        Ok(AuthenticationRefreshCommit::Superseded { token }) => {
            if verified_authentication_token(&token, identity, remote_domain, now_ms).is_some() {
                token
            } else {
                String::new()
            }
        }
        Err(err) => {
            lore_warn!("Failed to store refreshed authentication token: {err}");
            fallback_authentication_token(
                &current_token,
                &stored_token,
                identity,
                remote_domain,
                now_ms,
            )
        }
    }
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
/// token is never served an authorization that another credential produced.
///
/// Token store keys use `"{auth_url}/{repository_id}"` (no implementation-
/// specific prefix). The `Authentication` implementation handles resource ID
/// formatting internally.
///
/// A non-empty `identity_token` replaces the authentication token.
///
/// A non-empty `access_token` the authorization token.
pub async fn exchange(
    auth_url: &str,
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
    if auth_url.is_empty() {
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
        auth_url,
        identity,
        AuthzResource::Repository(repository),
        recipient_domain,
        identity_token,
    )
    .await
}

/// Exchanges an authentication token for an authorization token scoped to an
/// arbitrary resource identifier (non-repository). Mirrors `exchange` but
/// delegates to the implementation's `exchange_for_custom_resource`, letting
/// callers authorize against resources the `RepositoryId` model cannot express.
///
/// The `resource_id` is used verbatim as the cache/token-store key and is
/// passed unmodified to the auth backend.
///
/// `identity_token` and `access_token` are the caller-supplied credentials.
pub async fn exchange_custom_resource(
    auth_url: &str,
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
    if auth_url.is_empty() {
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
        auth_url,
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
    auth_url: &str,
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
    let credential_fingerprint = lore_credential::token_fingerprint(identity_token);
    let supplied_credentials = !credential_fingerprint.is_empty();
    // Token store key: "{auth_url}/{resource_id}" (no urc- prefix). A custom
    // resource ID takes the repository slot.
    let token_store_key = format!("{auth_url}/{resource_id}");
    let cache_key: AuthzKey = (
        auth_url.to_string(),
        identity.to_string(),
        resource_id,
        recipient_domain.clone(),
        credential_fingerprint,
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
        auth_url,
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
    auth_url: &str,
    identity: &str,
    resource: AuthzResource<'_>,
    recipient_domain: &str,
    identity_token: &str,
) -> Result<(String, Vec<String>), ExchangeError> {
    // Load authn token for the auth service domain
    lore_trace!("Authorizing using authn identity: {identity}");
    let auth_domain = get_domain_or_empty(auth_url);
    let Some(auth_service_only_token) = lore_credential::user_info(
        auth_url,
        identity,
        tokens_only_for_recipient_domain(auth_domain),
        identity_token,
        "",
    )
    .await
    else {
        lore_debug!("Not authenticated, unable to perform authz exchange");
        return Err(NotAuthenticated::new(format!(
            "no authentication token is stored for identity {identity} at {auth_url}; sign in again"
        ))
        .into());
    };
    lore_trace!("Authorizing using endpoint: {auth_url}");

    let time_start = Instant::now();

    // Delegate to the Authentication implementation
    let auth_impl = authentication::find(auth_url)
        .forward::<ExchangeError>("Unable to connect to auth exchange endpoint")?;
    // The correlation_id is no longer available from ExecutionContext in lore-transport.
    // Pass an empty string -- the gRPC interceptor may inject it from ambient state.
    let correlation_id = String::new();

    lore_trace!("Send auth exchange request");
    let authz = match resource {
        AuthzResource::Repository(repository) => {
            auth_impl
                .exchange_for_repository(
                    auth_url,
                    &auth_service_only_token.token,
                    repository,
                    &correlation_id,
                )
                .await
        }
        AuthzResource::Custom(resource_id) => {
            auth_impl
                .exchange_for_custom_resource(
                    auth_url,
                    &auth_service_only_token.token,
                    resource_id,
                    &correlation_id,
                )
                .await
        }
    }
    .map_err(|err| {
        if err.is_not_authorized() {
            ExchangeError::from(NotAuthorized)
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

/// Resolves an identity and obtains authentication/authorization tokens.
///
/// Returned tuple: (`authentication_token`, `authorization_token`, `resolved_identity`)
///
/// If `identity` is empty, iterates over available identities for the given
/// `auth_url` and tries to find one that can authenticate (and optionally
/// authorize for the given repository).
///
/// `identity_token` and `access_token` are the caller-supplied credentials.
pub async fn auth_exchange(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    repository: RepositoryId,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    if !identity.is_empty() {
        return auth_exchange_for_identity(
            auth_url,
            remote_domain,
            identity,
            repository,
            identity_token,
            access_token,
        )
        .await;
    }

    // No identity given, resolve one from available identities
    let Ok(identities) = token_store::load_identities(auth_url).await else {
        lore_debug!("No identities found for {auth_url}");
        return (String::new(), String::new(), String::new());
    };

    if repository.is_zero() {
        // No resource, pick first identity with a valid authn token
        for entry in &identities {
            let result =
                auth_exchange_for_identity(auth_url, remote_domain, entry, repository, "", "")
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
            auth_exchange_for_identity(auth_url, remote_domain, entry, repository, "", "").await;
        if !result.1.is_empty() {
            return result;
        }
    }

    lore_debug!("No identity could be authorized for repository {repository}");
    (String::new(), String::new(), String::new())
}

#[lore_macro::test_pub]
async fn auth_exchange_for_identity(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    repository: RepositoryId,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    let authentication_token = token_store::load_user_token(
        auth_url,
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
        refresh_authentication_if_needed(auth_url, remote_domain, identity, authentication_token)
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
            auth_url,
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
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    resource_id: &str,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    if !identity.is_empty() {
        return auth_exchange_custom_resource_for_identity(
            auth_url,
            remote_domain,
            identity,
            resource_id,
            identity_token,
            access_token,
        )
        .await;
    }

    let Ok(identities) = token_store::load_identities(auth_url).await else {
        lore_debug!("No identities found for {auth_url}");
        return (String::new(), String::new(), String::new());
    };

    // Store-resolved identities use store credentials, pass empty tokens.
    for entry in &identities {
        let result = auth_exchange_custom_resource_for_identity(
            auth_url,
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
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    resource_id: &str,
    identity_token: &str,
    access_token: &str,
) -> (String, String, String) {
    let authentication_token = token_store::load_user_token(
        auth_url,
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
        refresh_authentication_if_needed(auth_url, remote_domain, identity, authentication_token)
            .await
    } else {
        authentication_token
    };
    if identity_token.is_empty() && access_token.is_empty() && authentication_token.is_empty() {
        lore_debug!("Skipping identity {identity}, authn token is expired");
        return (String::new(), String::new(), String::new());
    }

    let authorization_token = exchange_custom_resource(
        auth_url,
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
