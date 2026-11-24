// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use lore_base::error::Disconnected;
use lore_base::error::NotAuthenticated;
use lore_base::error::NotSupported;
use lore_base::types::RepositoryId;
use lore_credential::token_store;
use lore_transport::auth::AuthEndpoint;
use lore_transport::auth::authentication;
use lore_transport::auth::exchange::*;
use lore_transport::error::ProtocolError;
use lore_transport::traits::Authentication;
use lore_transport::types::AuthSession;
use lore_transport::types::AuthenticationToken;
use lore_transport::types::AuthorizationToken;

use super::stub::AUTHN_ONE;
use super::stub::AUTHN_TWO;
use super::stub::AUTHZ_ONE;
use super::stub::AUTHZ_TWO;
use super::stub::StubAuthentication;

/// A supplied access token is the authorization token, so the exchange is
/// skipped entirely -- including the checks that would otherwise reject a
/// call with no auth URL and no identity.
#[tokio::test]
async fn supplied_access_token_replaces_the_repository_exchange() {
    let token = exchange(
        &AuthEndpoint::none(),
        "",
        RepositoryId::default(),
        "example.com".to_string(),
        "",
        "supplied-authz",
    )
    .await
    .expect("the supplied access token is used as given");
    assert_eq!(token, "supplied-authz");
}

#[tokio::test]
async fn supplied_access_token_replaces_the_resource_exchange() {
    let token = exchange_custom_resource(
        &AuthEndpoint::none(),
        "",
        "",
        "example.com".to_string(),
        "",
        "supplied-authz",
    )
    .await
    .expect("the supplied access token is used as given");
    assert_eq!(token, "supplied-authz");
}

/// An access token on its own authorizes without an authentication token to
/// trade in, and without reading one from the store. The authentication slot
/// comes back empty, so the services that need one fail where they use it
/// while the authorized ones still work.
#[tokio::test]
async fn access_token_alone_authorizes_without_an_authentication_token() {
    let repository: RepositoryId = "00112233445566778899aabbccddeeff"
        .parse()
        .expect("a valid repository id");
    let (authentication_token, authorization_token, identity) = auth_exchange(
        &AuthEndpoint::resolve("ucs-auth://auth.example.com").expect("a registered scheme"),
        "example.com",
        "alice",
        repository,
        "",
        "supplied-authz",
    )
    .await;

    assert!(
        authentication_token.is_empty(),
        "no authentication token is invented, and none is read from the store"
    );
    assert_eq!(authorization_token, "supplied-authz");
    assert_eq!(identity, "alice");
}

/// Without a repository, a supplied access token is still the authorization token, so the
/// repository service, which needs no repository, has a credential to present.
#[tokio::test]
async fn access_token_alone_authorizes_without_a_repository() {
    let (authentication_token, authorization_token, identity) = auth_exchange(
        &AuthEndpoint::resolve("ucs-auth://auth.example.com").expect("a registered scheme"),
        "example.com",
        "alice",
        RepositoryId::default(),
        "",
        "supplied-authz",
    )
    .await;

    assert!(authentication_token.is_empty());
    assert_eq!(authorization_token, "supplied-authz");
    assert_eq!(identity, "alice");
}

#[tokio::test]
async fn no_auth_endpoint_with_an_identity_sends_an_unsigned_identity_token() {
    let (authentication_token, authorization_token, identity) = auth_exchange(
        &AuthEndpoint::none(),
        "example.com",
        "alice",
        RepositoryId::default(),
        "",
        "",
    )
    .await;

    assert_eq!(authentication_token, authorization_token);
    assert_eq!(
        lore_credential::identity_from_token(&authorization_token),
        "alice"
    );
    assert_eq!(identity, "alice");
}

#[tokio::test]
async fn no_auth_endpoint_without_an_identity_sends_no_token() {
    let tokens = auth_exchange(
        &AuthEndpoint::none(),
        "example.com",
        "",
        RepositoryId::default(),
        "",
        "",
    )
    .await;
    assert_eq!(tokens, (String::new(), String::new(), String::new()));
}

#[tokio::test]
async fn no_auth_endpoint_sends_a_supplied_access_token_over_an_unsigned_one() {
    let (_, authorization_token, _) = auth_exchange(
        &AuthEndpoint::none(),
        "example.com",
        "alice",
        "00112233445566778899aabbccddeeff"
            .parse()
            .expect("a valid repository id"),
        "",
        "supplied-authz",
    )
    .await;
    assert_eq!(authorization_token, "supplied-authz");
}

#[tokio::test]
async fn no_auth_endpoint_sends_an_unsigned_identity_token_for_a_custom_resource() {
    let (_, authorization_token, identity) = auth_exchange_custom_resource(
        &AuthEndpoint::none(),
        "example.com",
        "alice",
        "some-resource",
        "",
        "",
    )
    .await;
    assert_eq!(
        lore_credential::identity_from_token(&authorization_token),
        "alice"
    );
    assert_eq!(identity, "alice");
}

#[tokio::test]
async fn no_auth_endpoint_sends_a_supplied_identity_token_over_an_unsigned_one() {
    let (authentication_token, _, _) = auth_exchange(
        &AuthEndpoint::none(),
        "example.com",
        "alice",
        RepositoryId::default(),
        "supplied-authn",
        "",
    )
    .await;
    assert_ne!(
        lore_credential::identity_from_token(&authentication_token),
        "alice",
        "the supplied token is not replaced with an unsigned one"
    );
}

/// Without one, the same call fails: nothing about the short circuit above
/// leaks into the normal path.
#[tokio::test]
async fn no_supplied_access_token_still_requires_an_auth_url() {
    let result = exchange(
        &AuthEndpoint::none(),
        "",
        RepositoryId::default(),
        "example.com".to_string(),
        "",
        "",
    )
    .await;
    assert!(result.is_err());
}

static REFRESH_TEST_MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static REFRESH_TEST_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

// CR-017(a): a full transport reset must evict the authz-exchange cache --
// it has no expiry-driven eviction of its own, so a post-logout identity
// switch would otherwise be able to reuse the previous identity's tokens.

#[tokio::test]
async fn clear_authz_cache_evicts_seeded_entry() {
    let _guard = refresh_test_guard().await;
    let key = (
        "https://auth.cr017-test.example".to_string(),
        "identity-cr017".to_string(),
        "resource-cr017".to_string(),
        "domain-cr017.example".to_string(),
        String::new(),
        lore_transport::connection::credential_store(),
    );
    cache()
        .tokens
        .lock()
        .insert(key.clone(), "token-value".to_string());

    clear_authz_cache().await;

    assert!(!cache().tokens.lock().contains_key(&key));
}

#[tokio::test]
async fn clear_authz_cache_is_noop_when_never_populated() {
    let _guard = refresh_test_guard().await;
    // `AUTHZ_CACHE` is a process-global `OnceLock` shared with every other
    // test in this crate's test binary, so this can't prove the OnceLock
    // is literally unset when this runs -- it proves the no-op path
    // (nothing to clear, or already cleared) doesn't panic either way.
    clear_authz_cache().await;
    clear_authz_cache().await;
}

struct TestAuthentication {
    refresh_result: Result<AuthenticationToken, ProtocolError>,
    refresh_never_completes: bool,
    authorization_token: String,
    refresh_calls: AtomicUsize,
    repository_calls: AtomicUsize,
    custom_resource_calls: AtomicUsize,
}

impl TestAuthentication {
    fn succeeding(refreshed: AuthenticationToken, authorization_token: String) -> Self {
        Self {
            refresh_result: Ok(refreshed),
            refresh_never_completes: false,
            authorization_token,
            refresh_calls: AtomicUsize::new(0),
            repository_calls: AtomicUsize::new(0),
            custom_resource_calls: AtomicUsize::new(0),
        }
    }

    fn failing(error: ProtocolError) -> Self {
        Self {
            refresh_result: Err(error),
            refresh_never_completes: false,
            authorization_token: String::new(),
            refresh_calls: AtomicUsize::new(0),
            repository_calls: AtomicUsize::new(0),
            custom_resource_calls: AtomicUsize::new(0),
        }
    }

    fn never_completing() -> Self {
        Self {
            refresh_result: Err(ProtocolError::internal("unreachable refresh result")),
            refresh_never_completes: true,
            authorization_token: String::new(),
            refresh_calls: AtomicUsize::new(0),
            repository_calls: AtomicUsize::new(0),
            custom_resource_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Authentication for TestAuthentication {
    async fn start_auth_session(
        &self,
        _auth_url: &str,
        _client_state: &str,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "start_auth_session".to_string(),
        }))
    }

    async fn poll_auth_session(
        &self,
        _auth_url: &str,
        _client_state: &str,
        _session_code: &str,
        _correlation_id: &str,
    ) -> Result<lore_transport::types::AuthSessionPoll, ProtocolError> {
        Ok(lore_transport::types::AuthSessionPoll::Pending)
    }

    async fn exchange_external_token(
        &self,
        _auth_url: &str,
        _token: &str,
        _token_type: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "exchange_external_token".to_string(),
        }))
    }

    async fn authenticate_client(
        &self,
        _auth_url: &str,
        _client_id: &str,
        _client_secret: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "authenticate_client".to_string(),
        }))
    }

    async fn revoke_refresh_token(
        &self,
        _auth_url: &str,
        _refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "revoke_refresh_token".to_string(),
        }))
    }

    async fn refresh_authentication(
        &self,
        _auth_url: &str,
        _refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        if self.refresh_never_completes {
            std::future::pending::<()>().await;
        }
        self.refresh_result.clone()
    }

    async fn exchange_for_repository(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        self.repository_calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorizationToken {
            token: self.authorization_token.clone(),
            expires_ms: u64::MAX,
            acceptable_root_domains: Vec::new(),
        })
    }

    async fn exchange_for_custom_resources(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _resource_ids: &[&str],
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        self.custom_resource_calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorizationToken {
            token: self.authorization_token.clone(),
            expires_ms: u64::MAX,
            acceptable_root_domains: Vec::new(),
        })
    }
}

async fn refresh_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    REFRESH_TEST_MUTEX
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn setup_refresh_test() {
    let path = REFRESH_TEST_PATH.get_or_init(|| {
        std::env::temp_dir().join(format!("lore-cr020-exchange-{}", std::process::id()))
    });
    unsafe {
        std::env::set_var("LORE_AUTH_PATH", path);
        std::env::set_var("LORE_AUTH_STORE", "fallback");
    }
    token_store::reset_tokens()
        .await
        .expect("reset test token store");
    cache().tokens.lock().clear();
}

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

fn jwt(identity: &str, expires_ms: u64, audience: &str) -> String {
    let header = base64_url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = format!(
        r#"{{"iss":"auth.example.com","sub":"{identity}","name":"Test User","exp":{},"aud":["{audience}"]}}"#,
        expires_ms / 1_000
    );
    format!("{header}.{}.", base64_url(payload.as_bytes()))
}

fn authentication_token(token: String, identity: &str) -> AuthenticationToken {
    AuthenticationToken {
        token,
        user_id: identity.to_string(),
        user_name: "Test User".to_string(),
        expires_ms: u64::MAX,
        acceptable_root_domains: Vec::new(),
        refresh_token: Some("refresh-new".to_string()),
        refresh_expires_ms: 0,
        scope: None,
    }
}

async fn store_pair(auth_url: &str, identity: &str, token: &str) {
    token_store::store_user_token_and_refresh_token(
        auth_url,
        identity,
        token,
        vec!["example.com".to_string()],
        Some("refresh-old"),
        0,
        None,
    )
    .await
    .expect("store authentication pair");
}

async fn replace_stored_pair_with_wrong_remote(
    auth_url: &str,
    identity: &str,
    current_token: &str,
    wrong_remote_token: &str,
) {
    store_pair(auth_url, identity, current_token).await;
    token_store::store_user_token(
        auth_url,
        identity,
        wrong_remote_token,
        vec!["attacker.example.net".to_string()],
    )
    .await
    .expect("replace stored token with wrong-remote token");
}

#[test]
fn authentication_refresh_due_is_false_before_lead_window() {
    assert!(!authentication_refresh_due(
        AUTHENTICATION_REFRESH_LEAD_MS + 1,
        0
    ));
}

#[test]
fn authentication_refresh_due_is_true_at_lead_boundary() {
    assert!(authentication_refresh_due(
        AUTHENTICATION_REFRESH_LEAD_MS,
        0
    ));
}

#[test]
fn authentication_refresh_due_saturates_near_maximum_time() {
    assert!(authentication_refresh_due(u64::MAX, u64::MAX - 1));
}

#[tokio::test]
async fn refresh_before_lead_window_keeps_token_without_calling_provider() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt(
        "alice",
        now + AUTHENTICATION_REFRESH_LEAD_MS + 60_000,
        "example.com",
    );
    let auth_url = "before-lead://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::failing(ProtocolError::internal(
        "must not refresh",
    )));
    authentication::add("before-lead", provider.clone()).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
    assert_eq!(provider.refresh_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refresh_without_stored_credential_keeps_still_valid_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let current = jwt("alice", current_time_ms() + 60_000, "example.com");
    let auth_url = "no-refresh://auth.example.com";
    token_store::store_user_token(auth_url, "alice", &current, vec!["example.com".to_string()])
        .await
        .expect("store authentication token");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
}

#[tokio::test]
async fn successful_refresh_replaces_stored_pair() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt("alice", now + 60_000, "example.com");
    let refreshed = jwt("alice", now + 3_600_000, "example.com");
    let auth_url = "refresh-success://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::succeeding(
        authentication_token(refreshed.clone(), "alice"),
        String::new(),
    ));
    authentication::add("refresh-success", provider.clone()).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current).await;

    assert_eq!(result, refreshed);
    assert_eq!(provider.refresh_calls.load(Ordering::SeqCst), 1);
    // Removing the login hands back the refresh token it held: the rotated one.
    let removed = token_store::remove_user_tokens_for_auth_url(auth_url, "alice")
        .await
        .expect("remove the login");
    let removed: Vec<_> = removed
        .into_iter()
        .map(|removed| removed.refresh_token)
        .collect();
    assert_eq!(removed, ["refresh-new"]);
}

#[tokio::test]
async fn transient_refresh_failure_keeps_still_valid_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let current = jwt("alice", current_time_ms() + 60_000, "example.com");
    let auth_url = "refresh-transient://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::failing(ProtocolError::from(
        Disconnected,
    )));
    authentication::add("refresh-transient", provider).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
}

#[tokio::test]
async fn never_completing_provider_times_out_to_still_valid_original_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let current = jwt("alice", current_time_ms() + 60_000, "example.com");
    let auth_url = "refresh-provider-timeout://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::never_completing());
    authentication::add("refresh-provider-timeout", provider.clone()).expect("register provider");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        refresh_authentication_if_needed_with_timeouts(
            auth_url,
            "repo.example.com",
            "alice",
            current.clone(),
            AuthenticationRefreshTimeouts {
                lock: Duration::from_millis(100),
                provider: Duration::from_millis(20),
            },
        ),
    )
    .await
    .expect("provider timeout did not bound refresh");

    assert_eq!(result, current);
    assert_eq!(provider.refresh_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn held_refresh_lease_times_out_to_still_valid_original_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let current = jwt("alice", current_time_ms() + 60_000, "example.com");
    let auth_url = "refresh-lock-timeout://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let held_lease = token_store::acquire_authentication_refresh(auth_url, "alice")
        .await
        .expect("hold refresh lease");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        refresh_authentication_if_needed_with_timeouts(
            auth_url,
            "repo.example.com",
            "alice",
            current.clone(),
            AuthenticationRefreshTimeouts {
                lock: Duration::from_millis(20),
                provider: Duration::from_millis(100),
            },
        ),
    )
    .await
    .expect("lease timeout did not bound refresh");

    assert_eq!(result, current);
    drop(held_lease);
    let reacquired = tokio::time::timeout(
        Duration::from_secs(1),
        token_store::acquire_authentication_refresh(auth_url, "alice"),
    )
    .await
    .expect("timed-out waiter ghost-locked the refresh lease")
    .expect("reacquire refresh lease after timeout");
    drop(reacquired);
}

#[tokio::test]
async fn rejected_refresh_keeps_still_valid_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let current = jwt("alice", current_time_ms() + 60_000, "example.com");
    let auth_url = "refresh-rejected://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::failing(ProtocolError::from(
        NotAuthenticated::new("refresh rejected"),
    )));
    authentication::add("refresh-rejected", provider).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
}

#[tokio::test]
async fn invalid_refreshed_jwt_keeps_still_valid_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let current = jwt("alice", current_time_ms() + 60_000, "example.com");
    let auth_url = "refresh-invalid://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::succeeding(
        authentication_token("not-a-jwt".to_string(), "alice"),
        String::new(),
    ));
    authentication::add("refresh-invalid", provider).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
}

#[tokio::test]
async fn refresh_failure_after_expiry_returns_login_required_empty_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let current = jwt(
        "alice",
        current_time_ms().saturating_sub(1_000),
        "example.com",
    );
    let auth_url = "refresh-expired://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::failing(ProtocolError::from(
        Disconnected,
    )));
    authentication::add("refresh-expired", provider).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current).await;

    assert!(result.is_empty());
}

#[tokio::test]
async fn missing_provider_does_not_return_reloaded_wrong_remote_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt("alice", now + 60_000, "example.com");
    let wrong_remote = jwt("alice", now + 60_000, "attacker.example.net");
    let auth_url = "missing-provider://auth.example.com";
    replace_stored_pair_with_wrong_remote(auth_url, "alice", &current, &wrong_remote).await;

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
    assert_ne!(result, wrong_remote);
}

#[tokio::test]
async fn provider_failure_does_not_return_reloaded_wrong_remote_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt("alice", now + 60_000, "example.com");
    let wrong_remote = jwt("alice", now + 60_000, "attacker.example.net");
    let auth_url = "wrong-remote-failure://auth.example.com";
    replace_stored_pair_with_wrong_remote(auth_url, "alice", &current, &wrong_remote).await;
    let provider = Arc::new(TestAuthentication::failing(ProtocolError::from(
        Disconnected,
    )));
    authentication::add("wrong-remote-failure", provider).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
    assert_ne!(result, wrong_remote);
}

#[tokio::test]
async fn invalid_refresh_does_not_return_reloaded_wrong_remote_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt("alice", now + 60_000, "example.com");
    let wrong_remote = jwt("alice", now + 60_000, "attacker.example.net");
    let auth_url = "wrong-remote-invalid://auth.example.com";
    replace_stored_pair_with_wrong_remote(auth_url, "alice", &current, &wrong_remote).await;
    let provider = Arc::new(TestAuthentication::succeeding(
        authentication_token("not-a-jwt".to_string(), "alice"),
        String::new(),
    ));
    authentication::add("wrong-remote-invalid", provider).expect("register provider");

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current.clone())
            .await;

    assert_eq!(result, current);
    assert_ne!(result, wrong_remote);
}

#[tokio::test]
async fn expired_original_token_fails_closed_when_reloaded_token_is_wrong_remote() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt("alice", now.saturating_sub(1_000), "example.com");
    let wrong_remote = jwt("alice", now + 60_000, "attacker.example.net");
    let auth_url = "wrong-remote-expired://auth.example.com";
    replace_stored_pair_with_wrong_remote(auth_url, "alice", &current, &wrong_remote).await;

    let result =
        refresh_authentication_if_needed(auth_url, "repo.example.com", "alice", current).await;

    assert!(result.is_empty());
    assert_ne!(result, wrong_remote);
}

#[tokio::test]
async fn repository_exchange_uses_refreshed_authentication_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt("alice", now + 60_000, "example.com");
    let refreshed = jwt("alice", now + 3_600_000, "example.com");
    let authz = jwt("alice", now + 3_600_000, "example.com");
    let auth_url = "refresh-repository://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::succeeding(
        authentication_token(refreshed.clone(), "alice"),
        authz,
    ));
    authentication::add("refresh-repository", provider.clone()).expect("register provider");

    let result = auth_exchange_for_identity(
        &AuthEndpoint::resolve(auth_url).expect("registered provider"),
        "repo.example.com",
        "alice",
        RepositoryId::from([1; 16]),
        "",
        "",
    )
    .await;

    assert_eq!(result.0.0, refreshed);
    assert_eq!(provider.repository_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn custom_resource_exchange_uses_refreshed_authentication_token() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    let now = current_time_ms();
    let current = jwt("alice", now + 60_000, "example.com");
    let refreshed = jwt("alice", now + 3_600_000, "example.com");
    let authz = jwt("alice", now + 3_600_000, "example.com");
    let auth_url = "refresh-custom://auth.example.com";
    store_pair(auth_url, "alice", &current).await;
    let provider = Arc::new(TestAuthentication::succeeding(
        authentication_token(refreshed.clone(), "alice"),
        authz,
    ));
    authentication::add("refresh-custom", provider.clone()).expect("register provider");

    let result = auth_exchange_custom_resource_for_identity(
        &AuthEndpoint::resolve(auth_url).expect("registered provider"),
        "repo.example.com",
        "alice",
        "bespoke-urc:test",
        "",
        "",
    )
    .await;

    assert_eq!(result.0, refreshed);
    assert_eq!(provider.custom_resource_calls.load(Ordering::SeqCst), 1);
}

/// An expired supplied token is still the credential the caller asked for.
///
/// Blanking it sends requests with no `Authorization` header at all, which a
/// server answers as an anonymous caller rather than as an expired one, so the
/// caller cannot tell its token needs renewing. Handing it over gets a straight
/// rejection instead. The expiry check that blanks a token exists to skip a
/// stale *stored* identity while picking one, which a supplied credential is
/// not.
///
/// The endpoint's implementation refuses every grant, so the authorization
/// exchange fails without a network call. The authentication token is what
/// this is about.
#[tokio::test]
async fn an_expired_supplied_identity_token_is_still_used() {
    /// The same claims as the fixtures above, with `exp` back in 2001.
    const EXPIRED_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJuYW1lIjoiQWxpY2UiLCJleHAiOjEwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdfQ.signature";

    let repository: RepositoryId = "00112233445566778899aabbccddeeff"
        .parse()
        .expect("a valid repository id");

    let refusing = AuthEndpoint::new(
        "stub-auth://auth.expired-token.test.invalid".to_string(),
        AuthEndpoint::none().auth,
    );
    let (authentication_token, _authorization_token, identity) = auth_exchange(
        &refusing,
        "example.com",
        "alice",
        repository,
        EXPIRED_TOKEN,
        "",
    )
    .await;

    assert_eq!(
        authentication_token, EXPIRED_TOKEN,
        "the supplied token must be handed over for the server to reject"
    );
    assert_eq!(identity, "alice");
}

/// An authorization is only good for the credential that earned it. Two
/// identity tokens for one user can carry different scopes, audiences or
/// lifetimes, so a caller supplying one must never be handed the
/// authorization another caller's token produced.
///
/// A stub `Authentication` returns a distinct authorization per
/// authentication token, which makes the separation observable: were the
/// cache shared across credentials, the second caller would come back with
/// the first one's token and no second exchange would happen. Binding the
/// stub as the endpoint's implementation also keeps this off the network.
#[tokio::test]
async fn one_supplied_credential_is_never_served_anothers_authorization() {
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "stub-auth://auth.credential-isolation.test.invalid";

    async fn authorize(
        endpoint: &AuthEndpoint,
        repository: RepositoryId,
        identity_token: &str,
    ) -> String {
        exchange(
            endpoint,
            "alice",
            repository,
            "example.com".to_string(),
            identity_token,
            "",
        )
        .await
        .expect("the stub authorizes")
    }

    let stub = StubAuthentication::new(|authn_token, _| {
        if authn_token == AUTHN_ONE {
            AUTHZ_ONE
        } else {
            AUTHZ_TWO
        }
    });
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    let repository: RepositoryId = "aabbccdd00112233aabbccdd00112233"
        .parse()
        .expect("a valid repository id");

    assert_eq!(authorize(&endpoint, repository, AUTHN_ONE).await, AUTHZ_ONE);
    assert_eq!(
        authorize(&endpoint, repository, AUTHN_ONE).await,
        AUTHZ_ONE,
        "the same credential reuses the authorization it earned"
    );
    assert_eq!(
        stub.exchanges(),
        1,
        "a repeat of the same credential must come from the cache"
    );

    assert_eq!(
        authorize(&endpoint, repository, AUTHN_TWO).await,
        AUTHZ_TWO,
        "a different credential must earn its own authorization"
    );
    assert_eq!(
        stub.exchanges(),
        2,
        "the second credential must not be served the first one's entry"
    );
}

// Single flight (WP-115): the cache lock guards only the map, so first touches
// of different keys exchange in parallel and concurrent misses on one key share
// one exchange. Each test registers its own scheme, so its keys are its own.

/// `sub` alice, `aud` example.com, expiring in 2033. Supplied as the identity
/// token, so no test here reads or writes the token store.
const SF_AUTHN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJleHAiOjIwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdLCJuYW1lIjoiQWxpY2UifQ.signature";

/// A repository exchanger that takes `delay` per call and records how many
/// calls ran at once. Call `n` (from 0) never completes when `n < hang_first`,
/// and fails when `n < fail_first`.
struct DelayedAuthentication {
    delay: Duration,
    token: String,
    hang_first: usize,
    fail_first: usize,
    calls: AtomicUsize,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: AtomicUsize,
}

impl DelayedAuthentication {
    fn new(delay: Duration) -> Self {
        Self {
            delay,
            token: jwt("alice", current_time_ms() + 3_600_000, "example.com"),
            hang_first: 0,
            fail_first: 0,
            calls: AtomicUsize::new(0),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// Counts one running exchange, also when the exchange is cancelled.
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Authentication for DelayedAuthentication {
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
    ) -> Result<lore_transport::types::AuthSessionPoll, ProtocolError> {
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

    async fn authenticate_client(
        &self,
        _auth_url: &str,
        _client_id: &str,
        _client_secret: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "authenticate_client".to_string(),
        }))
    }

    async fn revoke_refresh_token(
        &self,
        _auth_url: &str,
        _refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "revoke_refresh_token".to_string(),
        }))
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
        _repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let running = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        let _in_flight = InFlight(self.in_flight.clone());
        self.max_in_flight.fetch_max(running, Ordering::SeqCst);
        if call < self.hang_first {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(self.delay).await;
        if call < self.fail_first {
            return Err(ProtocolError::from(Disconnected));
        }
        Ok(AuthorizationToken {
            token: self.token.clone(),
            expires_ms: u64::MAX,
            acceptable_root_domains: vec!["example.com".to_string()],
        })
    }

    async fn exchange_for_custom_resources(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _resource_ids: &[&str],
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }
}

fn register_delayed(scheme: &str, provider: DelayedAuthentication) -> Arc<DelayedAuthentication> {
    let provider = Arc::new(provider);
    authentication::add(scheme, provider.clone()).expect("register provider");
    provider
}

async fn sf_exchange(auth_url: &str, repository: RepositoryId) -> Result<String, ExchangeError> {
    exchange(
        &AuthEndpoint::resolve(auth_url).expect("registered provider"),
        "alice",
        repository,
        "example.com".to_string(),
        SF_AUTHN,
        "",
    )
    .await
}

fn sf_key(auth_url: &str, repository: RepositoryId) -> AuthzKey {
    (
        auth_url.to_string(),
        "alice".to_string(),
        repository.to_string(),
        "example.com".to_string(),
        lore_credential::token_fingerprint(SF_AUTHN),
        lore_transport::connection::credential_store(),
    )
}

fn no_flight_for(key: &AuthzKey) -> bool {
    !cache().flights.lock().contains_key(key)
}

#[tokio::test]
async fn misses_on_different_keys_exchange_in_parallel() {
    let _guard = refresh_test_guard().await;
    const KEYS: u8 = 8;
    const DELAY: Duration = Duration::from_millis(200);
    let auth_url = "sf-parallel://auth.example.com";
    let provider = register_delayed("sf-parallel", DelayedAuthentication::new(DELAY));

    let started = std::time::Instant::now();
    let results = futures::future::join_all(
        (1..=KEYS).map(|n| sf_exchange(auth_url, RepositoryId::from([n; 16]))),
    )
    .await;
    let elapsed = started.elapsed();

    for result in results {
        assert_eq!(result.expect("each key authorizes"), provider.token);
    }
    assert_eq!(provider.calls(), usize::from(KEYS));
    assert_eq!(
        provider.max_in_flight.load(Ordering::SeqCst),
        usize::from(KEYS),
        "every key's exchange must run at once"
    );
    assert!(
        elapsed < DELAY * u32::from(KEYS) / 2,
        "{KEYS} keys at {DELAY:?} each took {elapsed:?}; the exchanges were serialized"
    );
}

#[tokio::test]
async fn concurrent_misses_on_one_key_share_one_exchange() {
    let _guard = refresh_test_guard().await;
    let auth_url = "sf-same-key://auth.example.com";
    let repository = RepositoryId::from([2; 16]);
    let provider = register_delayed(
        "sf-same-key",
        DelayedAuthentication::new(Duration::from_millis(200)),
    );

    let results =
        futures::future::join_all((0..8).map(|_| sf_exchange(auth_url, repository))).await;

    for result in results {
        assert_eq!(result.expect("every caller authorizes"), provider.token);
    }
    assert_eq!(
        provider.calls(),
        1,
        "the waiters must reuse the leader's token"
    );
    assert!(no_flight_for(&sf_key(auth_url, repository)));
}

#[tokio::test]
async fn a_failed_exchange_lets_the_next_caller_retry() {
    let _guard = refresh_test_guard().await;
    let auth_url = "sf-retry://auth.example.com";
    let repository = RepositoryId::from([3; 16]);
    let mut fake = DelayedAuthentication::new(Duration::from_millis(20));
    fake.fail_first = 1;
    let provider = register_delayed("sf-retry", fake);

    assert!(sf_exchange(auth_url, repository).await.is_err());
    assert!(
        !cache()
            .tokens
            .lock()
            .contains_key(&sf_key(auth_url, repository))
    );
    assert_eq!(
        sf_exchange(auth_url, repository)
            .await
            .expect("the retry authorizes"),
        provider.token
    );
    assert_eq!(provider.calls(), 2);
    assert!(no_flight_for(&sf_key(auth_url, repository)));
}

#[tokio::test]
async fn a_caller_waiting_behind_a_failed_exchange_runs_its_own() {
    let _guard = refresh_test_guard().await;
    let auth_url = "sf-retry-waiter://auth.example.com";
    let repository = RepositoryId::from([4; 16]);
    let mut fake = DelayedAuthentication::new(Duration::from_millis(100));
    fake.fail_first = 1;
    let provider = register_delayed("sf-retry-waiter", fake);

    let (leader, waiter) = tokio::join!(sf_exchange(auth_url, repository), async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        sf_exchange(auth_url, repository).await
    });

    assert!(leader.is_err(), "the leader sees its own failure");
    assert_eq!(waiter.expect("the waiter retries"), provider.token);
    assert_eq!(provider.calls(), 2);
    assert_eq!(provider.max_in_flight.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_cancelled_leader_does_not_wedge_its_waiters() {
    let _guard = refresh_test_guard().await;
    let auth_url = "sf-cancel-leader://auth.example.com";
    let repository = RepositoryId::from([5; 16]);
    let mut fake = DelayedAuthentication::new(Duration::from_millis(50));
    fake.hang_first = 1;
    let provider = register_delayed("sf-cancel-leader", fake);

    let leader = tokio::time::timeout(
        Duration::from_millis(150),
        sf_exchange(auth_url, repository),
    );
    let waiter = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        sf_exchange(auth_url, repository).await
    };
    let (leader, waiter) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(leader, waiter)
    })
    .await
    .expect("the waiter was wedged behind the cancelled leader");

    assert!(leader.is_err(), "the leader was cancelled by its timeout");
    assert_eq!(waiter.expect("the waiter authorizes"), provider.token);
    assert_eq!(provider.calls(), 2);
    assert_eq!(provider.in_flight.load(Ordering::SeqCst), 0);
    assert!(no_flight_for(&sf_key(auth_url, repository)));
}

#[tokio::test]
async fn a_cancelled_waiter_leaves_no_flight_behind() {
    let _guard = refresh_test_guard().await;
    let auth_url = "sf-cancel-waiter://auth.example.com";
    let repository = RepositoryId::from([6; 16]);
    let provider = register_delayed(
        "sf-cancel-waiter",
        DelayedAuthentication::new(Duration::from_millis(200)),
    );

    let (leader, waiter) = tokio::join!(sf_exchange(auth_url, repository), async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tokio::time::timeout(Duration::from_millis(30), sf_exchange(auth_url, repository)).await
    });

    assert_eq!(leader.expect("the leader authorizes"), provider.token);
    assert!(waiter.is_err(), "the waiter was cancelled by its timeout");
    assert!(no_flight_for(&sf_key(auth_url, repository)));
    assert_eq!(
        sf_exchange(auth_url, repository)
            .await
            .expect("a later caller authorizes"),
        provider.token
    );
    assert_eq!(
        provider.calls(),
        1,
        "the later caller is served from the cache"
    );
}

#[tokio::test]
async fn an_expired_cached_token_is_exchanged_again() {
    let _guard = refresh_test_guard().await;
    let auth_url = "sf-expiry://auth.example.com";
    let repository = RepositoryId::from([7; 16]);
    let provider = register_delayed(
        "sf-expiry",
        DelayedAuthentication::new(Duration::from_millis(10)),
    );
    let key = sf_key(auth_url, repository);
    let expired = jwt(
        "alice",
        current_time_ms().saturating_sub(1_000),
        "example.com",
    );
    cache().tokens.lock().insert(key.clone(), expired.clone());

    let token = sf_exchange(auth_url, repository)
        .await
        .expect("the expired entry is replaced");

    assert_eq!(token, provider.token);
    assert_ne!(token, expired);
    assert_eq!(provider.calls(), 1);
    assert_eq!(cache().tokens.lock().get(&key), Some(&provider.token));
    sf_exchange(auth_url, repository)
        .await
        .expect("the fresh entry is served");
    assert_eq!(provider.calls(), 1, "the fresh entry comes from the cache");
}

#[tokio::test]
async fn a_clear_waits_for_a_running_exchange_and_removes_its_entry() {
    let _guard = refresh_test_guard().await;
    const DELAY: Duration = Duration::from_millis(200);
    let auth_url = "sf-clear://auth.example.com";
    let repository = RepositoryId::from([8; 16]);
    let provider = register_delayed("sf-clear", DelayedAuthentication::new(DELAY));

    let started = std::time::Instant::now();
    let (exchanged, cleared_at) = tokio::join!(sf_exchange(auth_url, repository), async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        clear_authz_cache().await;
        started.elapsed()
    });

    assert_eq!(exchanged.expect("the exchange completes"), provider.token);
    assert!(
        cleared_at >= DELAY,
        "the clear returned after {cleared_at:?}, before the running exchange finished"
    );
    assert!(
        !cache()
            .tokens
            .lock()
            .contains_key(&sf_key(auth_url, repository)),
        "an exchange running across a clear must not repopulate the cache"
    );
}

// ---------------------------------------------------------------------------------------
// Error classes of a failed repository exchange survive `exchange()`: only NotAuthorized
// means "denied"; an auth-service NotFound must never read as a missing repository.
// ---------------------------------------------------------------------------------------

/// A repository exchanger that always fails with the error `make_error` builds.
struct FailingAuthentication {
    make_error: fn() -> ProtocolError,
}

#[async_trait]
impl Authentication for FailingAuthentication {
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
    ) -> Result<lore_transport::types::AuthSessionPoll, ProtocolError> {
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

    async fn authenticate_client(
        &self,
        _auth_url: &str,
        _client_id: &str,
        _client_secret: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "authenticate_client".to_string(),
        }))
    }

    async fn revoke_refresh_token(
        &self,
        _auth_url: &str,
        _refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "revoke_refresh_token".to_string(),
        }))
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
        _repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Err((self.make_error)())
    }

    async fn exchange_for_custom_resources(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _resource_ids: &[&str],
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }
}

fn register_failing(scheme: &str, make_error: fn() -> ProtocolError) {
    authentication::add(scheme, Arc::new(FailingAuthentication { make_error }))
        .expect("register provider");
}

fn denied_error() -> ProtocolError {
    ProtocolError::from(lore_base::error::NotAuthorized)
}

fn disconnected_error() -> ProtocolError {
    ProtocolError::from(Disconnected)
}

fn slow_down_error() -> ProtocolError {
    ProtocolError::from(lore_base::error::SlowDown)
}

fn not_authenticated_error() -> ProtocolError {
    ProtocolError::from(NotAuthenticated::new("auth said no".to_string()))
}

fn not_found_error() -> ProtocolError {
    ProtocolError::from(lore_base::error::NotFound)
}

#[tokio::test]
async fn a_denied_repository_exchange_stays_not_authorized() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-denied", denied_error);

    let err = sf_exchange("fe-denied://auth.example.com", RepositoryId::from([11; 16]))
        .await
        .expect_err("exchange must fail");

    assert!(err.is_not_authorized(), "{err:?}");
}

#[tokio::test]
async fn a_disconnected_repository_exchange_stays_disconnected() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-disconnected", disconnected_error);

    let err = sf_exchange(
        "fe-disconnected://auth.example.com",
        RepositoryId::from([12; 16]),
    )
    .await
    .expect_err("exchange must fail");

    assert!(err.is_disconnected(), "{err:?}");
    assert!(!err.is_not_authorized(), "{err:?}");
}

#[tokio::test]
async fn a_slow_down_repository_exchange_stays_slow_down() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-slow-down", slow_down_error);

    let err = sf_exchange(
        "fe-slow-down://auth.example.com",
        RepositoryId::from([13; 16]),
    )
    .await
    .expect_err("exchange must fail");

    assert!(err.is_slow_down(), "{err:?}");
    assert!(!err.is_not_authorized(), "{err:?}");
}

#[tokio::test]
async fn a_not_authenticated_repository_exchange_stays_not_authenticated() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-not-authenticated", not_authenticated_error);

    let err = sf_exchange(
        "fe-not-authenticated://auth.example.com",
        RepositoryId::from([14; 16]),
    )
    .await
    .expect_err("exchange must fail");

    assert!(err.is_not_authenticated(), "{err:?}");
    assert!(!err.is_not_authorized(), "{err:?}");
}

#[tokio::test]
async fn an_auth_service_not_found_is_internal_never_a_missing_repository() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-not-found", not_found_error);

    let err = sf_exchange(
        "fe-not-found://auth.example.com",
        RepositoryId::from([15; 16]),
    )
    .await
    .expect_err("exchange must fail");

    assert!(!err.is_not_found(), "{err:?}");
    assert!(!err.is_not_authorized(), "{err:?}");
    assert!(err.is_internal(), "{err:?}");
}

/// Runs the real `exchange()` as the policy's exchange effect, with counting reads.
async fn scoped_read_over_real_exchange(
    auth_url: &str,
    repository: RepositoryId,
) -> (
    Result<lore_transport::types::RepositoryData, ProtocolError>,
    usize,
    usize,
) {
    let scoped = AtomicUsize::new(0);
    let identity = AtomicUsize::new(0);
    let data = || lore_transport::types::RepositoryData {
        id: repository,
        name: "repo".to_string(),
        metadata: Default::default(),
        generation: None,
    };
    let result = lore_transport::grpc::scoped_repository_get(
        || sf_exchange(auth_url, repository),
        |_token| async {
            scoped.fetch_add(1, Ordering::SeqCst);
            Ok(data())
        },
        || async {
            identity.fetch_add(1, Ordering::SeqCst);
            Err(ProtocolError::from(lore_base::error::NotFound))
        },
    )
    .await;
    (
        result,
        scoped.load(Ordering::SeqCst),
        identity.load(Ordering::SeqCst),
    )
}

#[tokio::test]
async fn real_exchange_denied_falls_back_to_one_identity_read() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-policy-denied", denied_error);

    let (result, scoped, identity) = scoped_read_over_real_exchange(
        "fe-policy-denied://auth.example.com",
        RepositoryId::from([16; 16]),
    )
    .await;

    assert!(result.is_err_and(|err| err.is_not_found()));
    assert_eq!(identity, 1);
    assert_eq!(scoped, 0);
}

#[tokio::test]
async fn real_exchange_disconnected_returns_disconnected_with_no_reads() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-policy-disconnected", disconnected_error);

    let (result, scoped, identity) = scoped_read_over_real_exchange(
        "fe-policy-disconnected://auth.example.com",
        RepositoryId::from([17; 16]),
    )
    .await;

    assert!(result.is_err_and(|err| err.is_disconnected()));
    assert_eq!(identity, 0, "no fallback on a non-denial");
    assert_eq!(scoped, 0);
}

#[tokio::test]
async fn real_exchange_auth_not_found_does_not_read_as_a_missing_repository() {
    let _guard = refresh_test_guard().await;
    register_failing("fe-policy-not-found", not_found_error);

    let (result, scoped, identity) = scoped_read_over_real_exchange(
        "fe-policy-not-found://auth.example.com",
        RepositoryId::from([18; 16]),
    )
    .await;

    assert!(result.is_err_and(|err| !err.is_not_found()));
    assert_eq!(identity, 0);
    assert_eq!(scoped, 0);
}

/// An authorization the server refused is forgotten, so the next exchange asks for a new one, but
/// only while the cache still holds it: a refusal that arrives after the cache holds a newer one
/// leaves the newer one alone.
#[tokio::test]
async fn a_refusal_forgets_only_the_authorization_refused() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    let stub = StubAuthentication::new(|_, served| if served == 0 { AUTHZ_ONE } else { AUTHZ_TWO });
    let endpoint = AuthEndpoint::new(
        "stub-auth://auth.late-refusal.test.invalid".to_string(),
        stub.clone(),
    );
    let repository: RepositoryId = "aabbccdd00112233aabbccdd00112233"
        .parse()
        .expect("a valid repository id");
    let authorize = || {
        exchange(
            &endpoint,
            "alice",
            repository,
            "example.com".to_string(),
            AUTHN_ONE,
            "",
        )
    };
    let refuse = || {
        forget_refused_authorization(
            &endpoint,
            "alice",
            repository,
            "example.com",
            AUTHN_ONE,
            AUTHZ_ONE,
        )
    };

    assert_eq!(authorize().await.expect("authorized"), AUTHZ_ONE);
    refuse().await;
    assert_eq!(authorize().await.expect("authorized"), AUTHZ_TWO);
    refuse().await;
    assert_eq!(authorize().await.expect("authorized"), AUTHZ_TWO);
    assert_eq!(stub.exchanges(), 2);
}

/// A refusal that arrives after the token store holds a newer authorization leaves the newer one
/// in the store.
#[tokio::test]
async fn a_refusal_forgets_only_the_stored_authorization_refused() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "stub-auth://auth.late-stored-refusal.test.invalid";
    token_store::store_user_token(
        AUTH_URL,
        "alice",
        AUTHN_ONE,
        vec!["example.com".to_string()],
    )
    .await
    .expect("store the authentication token");
    let stub = StubAuthentication::new(|_, served| if served == 0 { AUTHZ_ONE } else { AUTHZ_TWO });
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());
    let repository: RepositoryId = "aabbccdd00112233aabbccdd44556677"
        .parse()
        .expect("a valid repository id");
    let authorize = || {
        exchange(
            &endpoint,
            "alice",
            repository,
            "example.com".to_string(),
            "",
            "",
        )
    };
    let refuse = || {
        forget_refused_authorization(&endpoint, "alice", repository, "example.com", "", AUTHZ_ONE)
    };

    assert_eq!(authorize().await.expect("authorized"), AUTHZ_ONE);
    refuse().await;
    assert_eq!(authorize().await.expect("authorized"), AUTHZ_TWO);
    refuse().await;

    let stored = token_store::load_user_token_from_store(
        &authorization_store_key(&endpoint, &repository.to_string()),
        "alice",
        token_store::vulnerable_all_tokens(),
    )
    .await;
    assert_eq!(stored.ok().as_deref(), Some(AUTHZ_TWO));
}

mod refused {
    use std::sync::Arc;
    use std::sync::Weak;

    use lore_base::lore_spawn_net;
    use lore_credential::token_store;
    use lore_transport::auth::AuthEndpoint;
    use lore_transport::auth::exchange::exchange;
    use lore_transport::connection::SuppliedCredentials;
    use lore_transport::error::ProtocolError;
    use lore_transport::quic::storage_service::client::StorageClient;
    use lore_transport::traits::Storage;

    use crate::auth::stub::*;
    use crate::quic::storage_service::test_server::SessionStarts;
    use crate::quic::storage_service::test_server::TestStorageServer;
    use crate::quic::storage_service::test_server::test_partition;
    use crate::quic::storage_service::test_server::wait_until;

    /// An auth service at `auth_url` that hands out the first authorization, then the second.
    fn auth_service(auth_url: &str) -> (AuthEndpoint, Arc<StubAuthentication>) {
        let stub =
            StubAuthentication::new(|_, served| if served == 0 { AUTHZ_ONE } else { AUTHZ_TWO });
        (AuthEndpoint::new(auth_url.to_string(), stub.clone()), stub)
    }

    /// A storage client for alice on `server`, through `endpoint`, with `credentials`.
    async fn connect(
        server: &TestStorageServer,
        endpoint: &AuthEndpoint,
        credentials: &Arc<SuppliedCredentials>,
    ) -> Arc<StorageClient> {
        StorageClient::connect(
            Weak::new(),
            &server.url,
            "example.com".to_string(),
            endpoint,
            "alice",
            test_partition(),
            credentials,
            None,
            lore_transport::quic::client::CongestionAlgorithm::default(),
        )
        .await
        .expect("connect to the test server")
    }

    /// A session start for alice through `endpoint` with `credentials`, on a server that refuses
    /// `refused`. Returns the server and what the session start returned.
    async fn session_start(
        endpoint: &AuthEndpoint,
        refused: &[&str],
        credentials: SuppliedCredentials,
    ) -> (TestStorageServer, Result<u32, ProtocolError>) {
        let server = TestStorageServer::start_refusing_authorizations(refused);
        let client = connect(&server, endpoint, &Arc::new(credentials)).await;
        let started = client.session_start(test_partition(), "test").await;
        (server, started)
    }

    /// A session start for alice through `endpoint` with `credentials`, which the server holds
    /// until a later call has supplied `identity_token` in their place, then refuses as not
    /// authorized, as it does every start after. Returns the server and what the session start
    /// returned.
    async fn session_start_across_a_rotation(
        endpoint: &AuthEndpoint,
        credentials: SuppliedCredentials,
        identity_token: &str,
    ) -> (TestStorageServer, Result<u32, ProtocolError>) {
        let (server, starts) = TestStorageServer::start_controlling_session_starts();
        starts
            .send(SessionStarts::Hold)
            .expect("the server holds starts");
        let credentials = Arc::new(credentials);
        let client = connect(&server, endpoint, &credentials).await;
        let starting =
            lore_spawn_net!(async move { client.session_start(test_partition(), "test").await });
        wait_until(
            || server.requested_session_starts_per_connection() == [1],
            "the session start did not reach the server",
        )
        .await;
        credentials.update(identity_token, "");
        starts
            .send(SessionStarts::RefuseAuthorization)
            .expect("the server refuses the held start");
        let started = starting.await.expect("session start task");
        (server, started)
    }

    /// A storage session start the server refuses forgets the authorization it presented and starts
    /// the session with a newly exchanged one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_authorization_is_exchanged_again() {
        // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
        let _guard = super::refresh_test_guard().await;
        let (endpoint, stub) = auth_service("stub-auth://auth.refused-authorization.test.invalid");
        let (server, started) = session_start(
            &endpoint,
            &[AUTHZ_ONE],
            SuppliedCredentials::new(AUTHN_ONE, ""),
        )
        .await;

        assert!(started.is_ok(), "the session must start: {started:?}");
        assert_eq!(server.presented_authorizations(), [AUTHZ_ONE, AUTHZ_TWO]);
        assert_eq!(stub.exchanges(), 2);
    }

    /// A refused authorization from the token store is not read back from it on the cache miss
    /// its eviction leaves, so the session starts with a newly exchanged one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_stored_authorization_is_exchanged_again() {
        // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
        let _guard = super::refresh_test_guard().await;
        const AUTH_URL: &str = "stub-auth://auth.refused-stored-authorization.test.invalid";
        token_store::store_user_token(
            AUTH_URL,
            "alice",
            AUTHN_ONE,
            vec!["example.com".to_string()],
        )
        .await
        .expect("store the authentication token");
        let (endpoint, stub) = auth_service(AUTH_URL);

        let (server, started) =
            session_start(&endpoint, &[AUTHZ_ONE], SuppliedCredentials::default()).await;

        assert!(started.is_ok(), "the session must start: {started:?}");
        assert_eq!(server.presented_authorizations(), [AUTHZ_ONE, AUTHZ_TWO]);
        assert_eq!(stub.exchanges(), 2);
    }

    /// A refusal of the newly exchanged authorization is final.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_new_authorization_is_final() {
        // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
        let _guard = super::refresh_test_guard().await;
        let (endpoint, stub) = auth_service("stub-auth://auth.refused-twice.test.invalid");
        let (server, started) = session_start(
            &endpoint,
            &[AUTHZ_ONE, AUTHZ_TWO],
            SuppliedCredentials::new(AUTHN_ONE, ""),
        )
        .await;

        assert!(started.is_err_and(|err| err.is_not_authorized()));
        assert_eq!(server.presented_authorizations(), [AUTHZ_ONE, AUTHZ_TWO]);
        assert_eq!(stub.exchanges(), 2);
    }

    /// A refusal is final where the exchange after it gives the authorization refused again, which
    /// is not presented twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refusal_the_exchange_gives_again_is_final() {
        // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
        let _guard = super::refresh_test_guard().await;
        let stub = StubAuthentication::new(|_, _| AUTHZ_ONE);
        let endpoint = AuthEndpoint::new(
            "stub-auth://auth.refused-unchanged.test.invalid".to_string(),
            stub.clone(),
        );
        let (server, started) = session_start(
            &endpoint,
            &[AUTHZ_ONE],
            SuppliedCredentials::new(AUTHN_ONE, ""),
        )
        .await;

        assert!(started.is_err_and(|err| err.is_not_authorized()));
        assert_eq!(server.presented_authorizations(), [AUTHZ_ONE]);
        assert_eq!(stub.exchanges(), 2);
    }

    /// A refusal of an access token the caller supplied is final, and asks the auth service
    /// nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_supplied_access_token_is_final() {
        // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
        let _guard = super::refresh_test_guard().await;
        let (endpoint, stub) = auth_service("stub-auth://auth.refused-access-token.test.invalid");
        let (server, started) = session_start(
            &endpoint,
            &[AUTHZ_ONE],
            SuppliedCredentials::new("", AUTHZ_ONE),
        )
        .await;

        assert!(started.is_err_and(|err| err.is_not_authorized()));
        assert_eq!(server.presented_authorizations(), [AUTHZ_ONE]);
        assert_eq!(stub.exchanges(), 0);
    }

    /// A refusal of an access token the caller supplied is final, and asks the auth service
    /// nothing, though a later call supplies an identity token while the server considers it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_supplied_access_token_is_final_after_a_rotation() {
        // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
        let _guard = super::refresh_test_guard().await;
        let (endpoint, stub) = auth_service("stub-auth://auth.rotated-access-token.test.invalid");
        let (server, started) = session_start_across_a_rotation(
            &endpoint,
            SuppliedCredentials::new("", AUTHZ_ONE),
            AUTHN_ONE,
        )
        .await;

        assert!(started.is_err_and(|err| err.is_not_authorized()));
        assert_eq!(server.presented_authorizations(), [AUTHZ_ONE]);
        assert_eq!(stub.exchanges(), 0);
    }

    /// A refusal is forgotten under the identity token that exchanged the authorization refused,
    /// though a later call supplies another while the server considers it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refusal_after_a_rotation_forgets_the_authorization_refused() {
        // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
        let _guard = super::refresh_test_guard().await;
        let (endpoint, stub) = auth_service("stub-auth://auth.rotated-identity-token.test.invalid");
        let (server, started) = session_start_across_a_rotation(
            &endpoint,
            SuppliedCredentials::new(AUTHN_ONE, ""),
            AUTHN_TWO,
        )
        .await;

        assert!(started.is_err_and(|err| err.is_not_authorized()));
        assert_eq!(server.presented_authorizations(), [AUTHZ_ONE, AUTHZ_TWO]);
        let authorized = exchange(
            &endpoint,
            "alice",
            test_partition(),
            "example.com".to_string(),
            AUTHN_ONE,
            "",
        )
        .await
        .expect("authorized");
        assert_eq!(authorized, AUTHZ_TWO);
        assert_eq!(stub.exchanges(), 3);
    }
}

/// An implementation that refuses the login token reports `NotAuthenticated`, and the
/// exchange passes it on as such, with the remote's reason on its trace, rather than as an
/// internal failure, so the caller can tell that logging in again fixes it. The same holds
/// for a refused partition and `NotAuthorized`.
#[tokio::test]
async fn a_refusal_of_the_login_token_stays_not_authenticated() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    use lore_transport::error::ProtocolError;
    use lore_transport::traits::Authentication;
    use lore_transport::types::AuthSession;
    use lore_transport::types::AuthSessionPoll;
    use lore_transport::types::AuthenticationToken;
    use lore_transport::types::AuthorizationToken;

    /// `sub` alice, `aud` example.com, expiring in 2033.
    const AUTHN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJleHAiOjIwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdLCJuYW1lIjoiQWxpY2UifQ.signature";

    /// The reason the stub's remote gives for each refusal.
    const REASON: &str = "the login expired";

    /// Refuses every exchange with the error it holds.
    struct Refusing(fn() -> ProtocolError);

    fn unused() -> ProtocolError {
        ProtocolError::internal("the stub only serves authorization exchanges")
    }

    #[async_trait::async_trait]
    impl Authentication for Refusing {
        async fn exchange_for_repository(
            &self,
            _auth_url: &str,
            _authn_token: &str,
            _repository: RepositoryId,
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            Err((self.0)())
        }

        async fn exchange_for_custom_resources(
            &self,
            _auth_url: &str,
            _authn_token: &str,
            _resource_ids: &[&str],
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            Err((self.0)())
        }

        async fn start_auth_session(
            &self,
            _auth_url: &str,
            _client_state: &str,
            _correlation_id: &str,
        ) -> Result<AuthSession, ProtocolError> {
            Err(unused())
        }

        async fn poll_auth_session(
            &self,
            _auth_url: &str,
            _client_state: &str,
            _session_code: &str,
            _correlation_id: &str,
        ) -> Result<AuthSessionPoll, ProtocolError> {
            Err(unused())
        }

        async fn exchange_external_token(
            &self,
            _auth_url: &str,
            _token: &str,
            _token_type: &str,
            _correlation_id: &str,
        ) -> Result<AuthenticationToken, ProtocolError> {
            Err(unused())
        }

        async fn authenticate_client(
            &self,
            _auth_url: &str,
            _client_id: &str,
            _client_secret: &str,
            _correlation_id: &str,
        ) -> Result<AuthenticationToken, ProtocolError> {
            Err(unused())
        }

        async fn refresh_authentication(
            &self,
            _auth_url: &str,
            _refresh_token: &str,
            _correlation_id: &str,
        ) -> Result<AuthenticationToken, ProtocolError> {
            Err(unused())
        }

        async fn revoke_refresh_token(
            &self,
            _auth_url: &str,
            _refresh_token: &str,
            _correlation_id: &str,
        ) -> Result<(), ProtocolError> {
            Err(unused())
        }
    }

    async fn assert_refused_as(
        auth_url: &str,
        refusal: fn() -> ProtocolError,
        check: fn(&ExchangeError) -> bool,
    ) {
        let repository: RepositoryId = "ccddeeff00112233ccddeeff00112233"
            .parse()
            .expect("a valid repository id");
        let endpoint =
            AuthEndpoint::new(auth_url.to_string(), std::sync::Arc::new(Refusing(refusal)));

        let refused = exchange(
            &endpoint,
            "alice",
            repository,
            "example.com".to_string(),
            AUTHN,
            "",
        )
        .await
        .expect_err("the stub refuses the exchange");
        assert_refusal(auth_url, &refused, check);

        let refused = exchange_custom_resource(
            &endpoint,
            "alice",
            "urc-user-service",
            "example.com".to_string(),
            AUTHN,
            "",
        )
        .await
        .expect_err("the stub refuses the exchange");
        assert_refusal(auth_url, &refused, check);
    }

    fn assert_refusal(auth_url: &str, refused: &ExchangeError, check: fn(&ExchangeError) -> bool) {
        assert!(check(refused), "{auth_url}: {refused}");
        assert!(
            refused.trace().locations().iter().any(|location| location
                .context()
                .is_some_and(|context| context.contains(REASON))),
            "{auth_url}: {refused:?}"
        );
    }

    assert_refused_as(
        "stub-auth://auth.refused-login.test.invalid",
        || tonic::Status::unauthenticated(REASON).into(),
        ExchangeError::is_not_authenticated,
    )
    .await;
    assert_refused_as(
        "stub-auth://auth.refused-partition.test.invalid",
        || tonic::Status::permission_denied(REASON).into(),
        ExchangeError::is_not_authorized,
    )
    .await;
}

/// An unsigned JWT naming `subject` for `audience`, expiring at `exp`.
fn oidc_jwt(subject: &str, audience: &str, exp: u64) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let claims = serde_json::json!({"iss": "lore", "sub": subject, "aud": [audience], "exp": exp});
    format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

const EXPIRED: u64 = 1_000_000_000;
const REFRESHED_REFRESH_EXPIRES: u64 = 1_950_000_000_000;

fn refreshed(token: &str, refresh_token: &str) -> lore_transport::types::AuthenticationToken {
    lore_transport::types::AuthenticationToken {
        token: token.to_owned(),
        user_id: "alice".to_owned(),
        user_name: String::new(),
        expires_ms: 2_000_000_000_000,
        acceptable_root_domains: Vec::new(),
        refresh_token: Some(refresh_token.to_owned()),
        refresh_expires_ms: REFRESHED_REFRESH_EXPIRES,
        scope: None,
    }
}

/// A stored login whose token has expired is refreshed while an identity is picked, so the
/// identity is found and authenticated without a new login. The new token is stored with the
/// new refresh token's deadline, so the next derivation presents no refresh token.
#[tokio::test]
async fn an_expired_stored_login_is_refreshed() {
    // FORK-LOCAL (Tideshift): the CR-020 tests repoint the store's environment.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh.test.invalid";
    token_store::store_user_token_and_refresh_token(
        AUTH_URL,
        "alice",
        &oidc_jwt("alice", "example.com", EXPIRED),
        vec!["example.com".to_owned()],
        Some("refresh-1"),
        0,
        None,
    )
    .await
    .expect("store the login");
    let stub = StubAuthentication::refreshing(|_| Ok(refreshed(AUTHN_ONE, "refresh-2")));
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    for _ in 0..2 {
        let (authentication_token, _, identity) = auth_exchange(
            &endpoint,
            "example.com",
            "",
            RepositoryId::default(),
            "",
            "",
        )
        .await;
        assert_eq!(authentication_token, AUTHN_ONE);
        assert_eq!(identity, "alice");
    }
    assert_eq!(stub.presented(), ["refresh-1"]);
    assert_eq!(
        token_store::load_refresh_expires(AUTH_URL, "alice").await,
        Some(REFRESHED_REFRESH_EXPIRES)
    );
}

/// A refused refresh token skips the identity, as an expired login did before, and is not
/// presented again.
#[tokio::test]
async fn an_expired_stored_login_whose_refresh_is_refused_is_skipped() {
    // FORK-LOCAL (Tideshift): the CR-020 tests repoint the store's environment.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh-refused.test.invalid";
    token_store::store_user_token_and_refresh_token(
        AUTH_URL,
        "alice",
        &oidc_jwt("alice", "example.com", EXPIRED),
        vec!["example.com".to_owned()],
        Some("refresh-1"),
        0,
        None,
    )
    .await
    .expect("store the login");
    let stub = StubAuthentication::refreshing(|_| {
        Err(lore_base::error::NotAuthenticated::new("refused").into())
    });
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    for _ in 0..2 {
        let (authentication_token, _, identity) = auth_exchange(
            &endpoint,
            "example.com",
            "alice",
            RepositoryId::default(),
            "",
            "",
        )
        .await;
        assert!(authentication_token.is_empty());
        assert!(identity.is_empty());
    }
    assert_eq!(stub.presented(), ["refresh-1"]);
}

/// FORK (Tideshift): over the real gRPC auth backend, the stored refresh credential survives an
/// `Internal` answer (the grant reads as `Disconnected`, so it is put back and presented again)
/// and is dropped after `Unauthenticated`. Each case is its own server, so it counts its own
/// presentations.
#[tokio::test]
async fn a_stored_refresh_credential_survives_internal_and_not_unauthenticated() {
    let _guard = refresh_test_guard().await;
    for (code, presented) in [
        (tonic::Code::Internal, vec!["refresh-1", "refresh-1"]),
        (tonic::Code::Unauthenticated, vec!["refresh-1"]),
    ] {
        let (auth_url, bearers) = super::stub::status_answering_h2_server(code).await;
        token_store::store_user_token_and_refresh_token(
            &auth_url,
            "alice",
            &oidc_jwt("alice", "example.com", EXPIRED),
            vec!["example.com".to_owned()],
            Some("refresh-1"),
            0,
            None,
        )
        .await
        .expect("store the login");
        let endpoint = AuthEndpoint::new(
            auth_url,
            Arc::new(lore_transport::auth::ucs_auth::UcsAuthentication),
        );

        for _ in 0..2 {
            let (authentication_token, _, _) = auth_exchange(
                &endpoint,
                "example.com",
                "alice",
                RepositoryId::default(),
                "",
                "",
            )
            .await;
            assert!(authentication_token.is_empty(), "{code:?}");
        }
        assert_eq!(*bearers.lock(), presented, "{code:?}");
    }
}

/// A refreshed token is sent only where the issuer named in it allows: one naming another
/// domain is stored, and not handed out for this one.
#[tokio::test]
async fn a_refreshed_token_for_another_domain_is_not_handed_out() {
    // FORK-LOCAL (Tideshift): the CR-020 tests repoint the store's environment.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh-other-domain.test.invalid";
    token_store::store_user_token_and_refresh_token(
        AUTH_URL,
        "alice",
        &oidc_jwt("alice", "example.com", EXPIRED),
        vec!["example.com".to_owned()],
        Some("refresh-1"),
        0,
        None,
    )
    .await
    .expect("store the login");
    let elsewhere = oidc_jwt("alice", "elsewhere.test.invalid", 2_000_000_000);
    let refreshed_token = elsewhere.clone();
    let stub =
        StubAuthentication::refreshing(move |_| Ok(refreshed(&refreshed_token, "refresh-2")));
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    let (authentication_token, _, _) = auth_exchange(
        &endpoint,
        "example.com",
        "alice",
        RepositoryId::default(),
        "",
        "",
    )
    .await;

    assert!(authentication_token.is_empty());
    let stored = token_store::load_user_token_from_store(
        AUTH_URL,
        "alice",
        token_store::vulnerable_all_tokens(),
    )
    .await;
    assert_eq!(stored.ok(), Some(elsewhere));
}

/// A supplied identity token is handed over expired, as before: the store's refresh token is
/// for the stored login, not for a credential the caller supplied.
#[tokio::test]
async fn an_expired_supplied_identity_token_is_not_refreshed() {
    // FORK-LOCAL (Tideshift): the CR-020 tests repoint the store's environment.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh-supplied.test.invalid";
    let supplied = oidc_jwt("alice", "example.com", EXPIRED);
    token_store::store_user_token_and_refresh_token(
        AUTH_URL,
        "alice",
        &supplied,
        vec!["example.com".to_owned()],
        Some("refresh-1"),
        0,
        None,
    )
    .await
    .expect("store the login");
    let stub = StubAuthentication::refreshing(|_| Ok(refreshed(AUTHN_ONE, "refresh-2")));
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    let (authentication_token, _, _) = auth_exchange(
        &endpoint,
        "example.com",
        "alice",
        RepositoryId::default(),
        &supplied,
        "",
    )
    .await;

    assert_eq!(authentication_token, supplied);
    assert!(stub.presented().is_empty());
}

/// The partition exchange a connection makes before it authenticates trades a refreshed login
/// token, not the expired one, for the repository and for a custom resource alike.
#[tokio::test]
async fn an_exchange_refreshes_an_expired_stored_login_first() {
    // FORK-LOCAL (Tideshift): the CR-020 tests repoint the store's environment.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh-exchange.test.invalid";
    token_store::store_user_token_and_refresh_token(
        AUTH_URL,
        "alice",
        &oidc_jwt("alice", "example.com", EXPIRED),
        vec!["example.com".to_owned()],
        Some("refresh-1"),
        0,
        None,
    )
    .await
    .expect("store the login");
    let stub = StubAuthentication::refreshing(|_| Ok(refreshed(AUTHN_ONE, "refresh-2")));
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());
    let repository: RepositoryId = "aabbccdd00112233aabbccdd00112244"
        .parse()
        .expect("a valid repository id");

    let authorization = exchange(
        &endpoint,
        "alice",
        repository,
        "example.com".to_string(),
        "",
        "",
    )
    .await
    .expect("the exchange succeeds");
    assert_eq!(authorization, AUTHZ_ONE);

    let authorization = exchange_custom_resource(
        &endpoint,
        "alice",
        "urc-user-service",
        "example.com".to_string(),
        "",
        "",
    )
    .await
    .expect("the exchange succeeds");
    assert_eq!(authorization, AUTHZ_ONE);

    assert_eq!(stub.presented(), ["refresh-1"]);
}

/// A refresh that was not sent keeps the refresh token, which the next derivation presents
/// again. One that may have reached the issuer drops it, so it is never presented twice.
#[tokio::test]
async fn only_an_unsent_refresh_is_tried_again() {
    // FORK-LOCAL (Tideshift): the CR-020 tests repoint the store's environment.
    let _guard = refresh_test_guard().await;
    for (auth_url, failure, presented) in [
        (
            "oidc+https://refresh-unsent-again.test.invalid",
            (|| lore_base::error::Disconnected.into()) as fn() -> lore_transport::ProtocolError,
            2,
        ),
        (
            "oidc+https://refresh-maybe-sent.test.invalid",
            || lore_transport::ProtocolError::internal("the answer was lost"),
            1,
        ),
    ] {
        token_store::store_user_token_and_refresh_token(
            auth_url,
            "alice",
            &oidc_jwt("alice", "example.com", EXPIRED),
            vec!["example.com".to_owned()],
            Some("refresh-1"),
            0,
            None,
        )
        .await
        .expect("store the login");
        let stub = StubAuthentication::refreshing(move |_| Err(failure()));
        let endpoint = AuthEndpoint::new(auth_url.to_string(), stub.clone());

        for _ in 0..2 {
            let (authentication_token, _, _) = auth_exchange(
                &endpoint,
                "example.com",
                "alice",
                RepositoryId::default(),
                "",
                "",
            )
            .await;
            assert!(authentication_token.is_empty());
        }
        assert_eq!(stub.presented().len(), presented, "{auth_url}");
    }
}

/// A caller that gives up during a refresh, as a cancelled connection does, does not stop it:
/// the refresh completes and stores the new token, which the next caller uses without
/// presenting the refresh token again.
#[tokio::test]
async fn a_cancelled_caller_does_not_stop_the_refresh() {
    // FORK-LOCAL (Tideshift): the CR-020 tests repoint the store's environment.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh-caller-cancelled.test.invalid";
    token_store::store_user_token_and_refresh_token(
        AUTH_URL,
        "alice",
        &oidc_jwt("alice", "example.com", EXPIRED),
        vec!["example.com".to_owned()],
        Some("refresh-1"),
        0,
        None,
    )
    .await
    .expect("store the login");
    let stub = StubAuthentication::refreshing_after(std::time::Duration::from_millis(300), |_| {
        Ok(refreshed(AUTHN_ONE, "refresh-2"))
    });
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());
    let authenticate = || {
        auth_exchange(
            &endpoint,
            "example.com",
            "alice",
            RepositoryId::default(),
            "",
            "",
        )
    };

    let cancelled =
        tokio::time::timeout(std::time::Duration::from_millis(50), authenticate()).await;
    assert!(cancelled.is_err(), "the refresh outlasts the caller");

    let (authentication_token, _, _) = authenticate().await;
    assert_eq!(authentication_token, AUTHN_ONE);
    assert_eq!(stub.presented(), ["refresh-1"]);
}

fn a_repository() -> RepositoryId {
    "aabbccdd00112233aabbccdd8899aabb"
        .parse()
        .expect("a valid repository id")
}

/// Every identity and repository combination [`auth_exchange_for_stored_identity`] is asked
/// with: any stored identity or the one named, and with or without a repository.
fn identity_and_repository_cases() -> [(&'static str, RepositoryId); 4] {
    [
        ("", RepositoryId::default()),
        ("", a_repository()),
        ("alice", RepositoryId::default()),
        ("alice", a_repository()),
    ]
}

async fn store_expired_login(auth_url: &str, user: &str, refresh_token: Option<&str>) {
    token_store::store_user_token_and_refresh_token(
        auth_url,
        user,
        &oidc_jwt(user, "example.com", EXPIRED),
        vec!["example.com".to_owned()],
        refresh_token,
        0,
        None,
    )
    .await
    .expect("store the login");
}

#[tokio::test]
async fn a_stored_login_whose_refresh_is_refused_is_not_authenticated() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    for (case, (identity, repository)) in identity_and_repository_cases().into_iter().enumerate() {
        let auth_url = format!("oidc+https://dead-session-{case}.test.invalid");
        store_expired_login(&auth_url, "alice", Some("refresh-1")).await;
        let stub = StubAuthentication::refreshing(|_| {
            Err(NotAuthenticated::new("the issuer refused the refresh token").into())
        });
        let endpoint = AuthEndpoint::new(auth_url.clone(), stub.clone());

        let err = auth_exchange_for_stored_identity(&endpoint, "example.com", identity, repository)
            .await
            .expect_err("no identity resolves");

        assert!(err.is_not_authenticated(), "{auth_url}: {err}");
        assert_eq!(stub.presented(), ["refresh-1"], "{auth_url}");
        assert_eq!(stub.exchanges(), 0, "{auth_url}");
    }
}

#[tokio::test]
async fn an_expired_stored_login_without_a_refresh_token_is_not_authenticated() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    for (case, (identity, repository)) in identity_and_repository_cases().into_iter().enumerate() {
        let auth_url = format!("oidc+https://expired-no-refresh-{case}.test.invalid");
        store_expired_login(&auth_url, "alice", None).await;
        let endpoint = AuthEndpoint::new(auth_url.clone(), StubAuthentication::new(|_, _| ""));

        let err = auth_exchange_for_stored_identity(&endpoint, "example.com", identity, repository)
            .await
            .expect_err("no identity resolves");

        assert!(err.is_not_authenticated(), "{auth_url}: {err}");
    }
}

/// A refresh grant that could not be sent keeps the refresh token, so the session is not over:
/// the failure is `Disconnected`, and the next attempt presents the same refresh token.
#[tokio::test]
async fn an_unsent_refresh_is_disconnected() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    for (case, (identity, repository)) in identity_and_repository_cases().into_iter().enumerate() {
        let auth_url = format!("oidc+https://refresh-unsent-{case}.test.invalid");
        store_expired_login(&auth_url, "alice", Some("refresh-1")).await;
        let stub = StubAuthentication::refreshing(|_| Err(lore_base::error::Disconnected.into()));
        let endpoint = AuthEndpoint::new(auth_url.clone(), stub.clone());

        for _ in 0..2 {
            let err =
                auth_exchange_for_stored_identity(&endpoint, "example.com", identity, repository)
                    .await
                    .expect_err("no identity resolves");
            assert!(err.is_disconnected(), "{auth_url}: {err}");
        }
        assert_eq!(stub.presented(), ["refresh-1", "refresh-1"], "{auth_url}");
    }
}

#[tokio::test]
async fn no_stored_identity_is_not_authenticated() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    let endpoint = AuthEndpoint::new(
        "oidc+https://no-identity.test.invalid".to_string(),
        StubAuthentication::new(|_, _| ""),
    );

    let err = auth_exchange_for_stored_identity(&endpoint, "example.com", "", a_repository())
        .await
        .expect_err("no identity resolves");
    assert!(err.is_not_authenticated(), "{err}");
}

#[tokio::test]
async fn a_given_identity_without_a_stored_login_is_not_authenticated() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://given-identity.test.invalid";
    token_store::store_user_token(AUTH_URL, "alice", AUTHN_ONE, vec!["example.com".to_owned()])
        .await
        .expect("store the login");
    let endpoint = AuthEndpoint::new(
        AUTH_URL.to_string(),
        StubAuthentication::new(|_, _| AUTHZ_ONE),
    );

    let err =
        auth_exchange_for_stored_identity(&endpoint, "example.com", "bob", RepositoryId::default())
            .await
            .expect_err("bob has no login");
    assert!(err.is_not_authenticated(), "{err}");
}

/// A login that the remote's domain may not be sent is no credential for that remote.
#[tokio::test]
async fn a_stored_login_for_another_domain_is_not_authenticated() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://other-domain-login.test.invalid";
    token_store::store_user_token(
        AUTH_URL,
        "alice",
        &oidc_jwt("alice", "elsewhere.test.invalid", 2_000_000_000),
        vec!["elsewhere.test.invalid".to_owned()],
    )
    .await
    .expect("store the login");
    let stub = StubAuthentication::new(|_, _| AUTHZ_ONE);
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    let err = auth_exchange_for_stored_identity(&endpoint, "example.com", "", a_repository())
        .await
        .expect_err("no identity resolves");
    assert!(err.is_not_authenticated(), "{err}");
    assert_eq!(stub.exchanges(), 0);
}

/// A name, the error the exchange fails with, and the check the resulting error must pass.
type ExchangeFailureCase = (
    &'static str,
    fn() -> ProtocolError,
    fn(&ExchangeError) -> bool,
);

/// The exchange's own answer decides the failure: a refusal of the repository is
/// `NotAuthorized`, a refusal of the login token (one revoked at the issuer) is
/// `NotAuthenticated`, and an unreachable auth service is `Disconnected`.
#[tokio::test]
async fn a_failed_repository_exchange_keeps_its_kind() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    let cases: [ExchangeFailureCase; 3] = [
        (
            "refused",
            || lore_base::error::NotAuthorized.into(),
            ExchangeError::is_not_authorized,
        ),
        (
            "revoked",
            || NotAuthenticated::new("the login token was revoked").into(),
            ExchangeError::is_not_authenticated,
        ),
        (
            "unreachable",
            || lore_base::error::Disconnected.into(),
            ExchangeError::is_disconnected,
        ),
    ];
    for (name, exchange_error, expected) in cases {
        for identity in ["", "alice"] {
            let auth_url = format!(
                "oidc+https://exchange-{name}-{}.test.invalid",
                identity.len()
            );
            token_store::store_user_token(
                &auth_url,
                "alice",
                AUTHN_ONE,
                vec!["example.com".to_owned()],
            )
            .await
            .expect("store the login");
            let stub = StubAuthentication::failing_exchanges(exchange_error);
            let endpoint = AuthEndpoint::new(auth_url.clone(), stub.clone());

            let err = auth_exchange_for_stored_identity(
                &endpoint,
                "example.com",
                identity,
                a_repository(),
            )
            .await
            .expect_err("no identity is authorized");
            assert!(expected(&err), "{auth_url}: {err}");
            assert_eq!(stub.exchanges(), 1, "{auth_url}");

            let (authentication_token, _, resolved) = auth_exchange_for_stored_identity(
                &endpoint,
                "example.com",
                identity,
                RepositoryId::default(),
            )
            .await
            .expect("the identity authenticates");
            assert_eq!(authentication_token, AUTHN_ONE, "{auth_url}");
            assert_eq!(resolved, "alice", "{auth_url}");
        }
    }
}

/// With several stored identities, one that cannot authenticate does not hide another's refusal,
/// nor stop another from being picked.
#[tokio::test]
async fn a_dead_identity_does_not_hide_another_identitys_answer() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    const REFUSED: &str = "oidc+https://mixed-refused.test.invalid";
    store_expired_login(REFUSED, "alice", None).await;
    token_store::store_user_token(REFUSED, "bob", AUTHN_TWO, vec!["example.com".to_owned()])
        .await
        .expect("store bob's login");
    let refusing = AuthEndpoint::new(
        REFUSED.to_string(),
        StubAuthentication::failing_exchanges(|| lore_base::error::NotAuthorized.into()),
    );
    let err = auth_exchange_for_stored_identity(&refusing, "example.com", "", a_repository())
        .await
        .expect_err("no identity is authorized");
    assert!(err.is_not_authorized(), "{err}");

    const REFUSED_FIRST: &str = "oidc+https://mixed-refused-first.test.invalid";
    token_store::store_user_token(
        REFUSED_FIRST,
        "bob",
        AUTHN_TWO,
        vec!["example.com".to_owned()],
    )
    .await
    .expect("store bob's login");
    store_expired_login(REFUSED_FIRST, "alice", None).await;
    let refusing = AuthEndpoint::new(
        REFUSED_FIRST.to_string(),
        StubAuthentication::failing_exchanges(|| lore_base::error::NotAuthorized.into()),
    );
    let err = auth_exchange_for_stored_identity(&refusing, "example.com", "", a_repository())
        .await
        .expect_err("no identity is authorized");
    assert!(err.is_not_authorized(), "{err}");

    const AUTHORIZED: &str = "oidc+https://mixed-authorized.test.invalid";
    store_expired_login(AUTHORIZED, "alice", None).await;
    token_store::store_user_token(AUTHORIZED, "bob", AUTHN_TWO, vec!["example.com".to_owned()])
        .await
        .expect("store bob's login");
    let authorizing = AuthEndpoint::new(
        AUTHORIZED.to_string(),
        StubAuthentication::new(|_, _| AUTHZ_TWO),
    );
    let tokens = auth_exchange_for_stored_identity(&authorizing, "example.com", "", a_repository())
        .await
        .expect("bob is authorized");
    assert_eq!(
        tokens,
        (AUTHN_TWO.to_owned(), AUTHZ_TWO.to_owned(), "bob".to_owned())
    );
}

/// A grant that failed after it may have reached the issuer drops the refresh token, so the
/// session is over.
#[tokio::test]
async fn a_failed_refresh_is_not_authenticated() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh-failed-answer.test.invalid";
    store_expired_login(AUTH_URL, "alice", Some("refresh-1")).await;
    let stub = StubAuthentication::refreshing(|_| {
        Err(ProtocolError::internal("the answer could not be read"))
    });
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    for _ in 0..2 {
        let err = auth_exchange_for_stored_identity(
            &endpoint,
            "example.com",
            "",
            RepositoryId::default(),
        )
        .await
        .expect_err("no identity resolves");
        assert!(err.is_not_authenticated(), "{err}");
    }
    assert_eq!(stub.presented(), ["refresh-1"]);
}

/// The partition exchange refreshes an expired login first, and a grant that could not be sent
/// fails the exchange as `Disconnected`, for the repository and for a custom resource alike.
#[tokio::test]
async fn an_exchange_whose_refresh_is_unsent_is_disconnected() {
    // FORK-LOCAL (Tideshift): the fork's refresh tests repoint LORE_AUTH_PATH; hold their guard.
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "oidc+https://refresh-exchange-unsent.test.invalid";
    store_expired_login(AUTH_URL, "alice", Some("refresh-1")).await;
    let stub = StubAuthentication::refreshing(|_| Err(lore_base::error::Disconnected.into()));
    let endpoint = AuthEndpoint::new(AUTH_URL.to_string(), stub.clone());

    let err = exchange(
        &endpoint,
        "alice",
        a_repository(),
        "example.com".to_string(),
        "",
        "",
    )
    .await
    .expect_err("the refresh was not sent");
    assert!(err.is_disconnected(), "{err}");

    let err = exchange_custom_resource(
        &endpoint,
        "alice",
        "urc-user-service",
        "example.com".to_string(),
        "",
        "",
    )
    .await
    .expect_err("the refresh was not sent");
    assert!(err.is_disconnected(), "{err}");
    assert_eq!(stub.presented(), ["refresh-1", "refresh-1"]);
    assert_eq!(stub.exchanges(), 0);
}
