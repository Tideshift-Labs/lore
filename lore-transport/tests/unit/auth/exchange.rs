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
use lore_transport::auth::authentication;
use lore_transport::auth::exchange::*;
use lore_transport::error::ProtocolError;
use lore_transport::traits::Authentication;
use lore_transport::types::AuthSession;
use lore_transport::types::AuthenticationToken;
use lore_transport::types::AuthorizationToken;

/// A supplied access token is the authorization token, so the exchange is
/// skipped entirely -- including the checks that would otherwise reject a
/// call with no auth URL and no identity.
#[tokio::test]
async fn supplied_access_token_replaces_the_repository_exchange() {
    let token = exchange(
        "",
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
    let token =
        exchange_custom_resource("", "", "", "example.com".to_string(), "", "supplied-authz")
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
        "ucs-auth://auth.example.com",
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

/// Without one, the same call fails: nothing about the short circuit above
/// leaks into the normal path.
#[tokio::test]
async fn no_supplied_access_token_still_requires_an_auth_url() {
    let result = exchange(
        "",
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
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        Ok(None)
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

    async fn exchange_for_custom_resource(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _resource_id: &str,
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
    }
}

async fn store_pair(auth_url: &str, identity: &str, token: &str) {
    token_store::store_user_token(auth_url, identity, token, vec!["example.com".to_string()])
        .await
        .expect("store authentication token");
    token_store::store_refresh_token(auth_url, identity, "refresh-old")
        .await
        .expect("store refresh credential");
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
    assert_eq!(
        token_store::load_refresh_token(auth_url, "alice")
            .await
            .expect("load replacement refresh credential"),
        "refresh-new"
    );
    assert_eq!(provider.refresh_calls.load(Ordering::SeqCst), 1);
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
        auth_url,
        "repo.example.com",
        "alice",
        RepositoryId::from([1; 16]),
        "",
        "",
    )
    .await;

    assert_eq!(result.0, refreshed);
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
        auth_url,
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
/// The auth URL uses a scheme no `Authentication` implementation is registered
/// for, so the authorization exchange fails without a network call. The
/// authentication token is what this is about.
#[tokio::test]
async fn an_expired_supplied_identity_token_is_still_used() {
    /// The same claims as the fixtures above, with `exp` back in 2001.
    const EXPIRED_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJuYW1lIjoiQWxpY2UiLCJleHAiOjEwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdfQ.signature";

    let repository: RepositoryId = "00112233445566778899aabbccddeeff"
        .parse()
        .expect("a valid repository id");

    let (authentication_token, _authorization_token, identity) = auth_exchange(
        "no-such-scheme://auth.expired-token.test.invalid",
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
/// the first one's token and no second exchange would happen. Registering the
/// stub under its own scheme also keeps this off the network.
#[tokio::test]
async fn one_supplied_credential_is_never_served_anothers_authorization() {
    let _guard = refresh_test_guard().await;
    use lore_transport::error::ProtocolError;
    use lore_transport::traits::Authentication;
    use lore_transport::types::AuthSession;
    use lore_transport::types::AuthenticationToken;
    use lore_transport::types::AuthorizationToken;

    /// `sub` alice, `aud` example.com, expiring in 2033.
    const AUTHN_ONE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJleHAiOjIwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdLCJuYW1lIjoiQWxpY2UifQ.signature";
    /// The same user, a different credential -- note the `scope` claim.
    const AUTHN_TWO: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJleHAiOjIwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdLCJuYW1lIjoiQWxpY2UiLCJzY29wZSI6InJlYWQifQ.signature";
    const AUTHZ_ONE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJleHAiOjIwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdLCJuYW1lIjoiQWxpY2UiLCJhdXRoeiI6Im9uZSJ9.signature";
    const AUTHZ_TWO: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJleHAiOjIwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdLCJuYW1lIjoiQWxpY2UiLCJhdXRoeiI6InR3byJ9.signature";
    const AUTH_URL: &str = "stub-auth://auth.credential-isolation.test.invalid";

    /// Hands back an authorization naming which authentication token asked
    /// for it, and counts the exchanges that actually happened.
    struct StubAuthentication {
        exchanges: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Authentication for StubAuthentication {
        async fn exchange_for_repository(
            &self,
            _auth_url: &str,
            authn_token: &str,
            _repository: RepositoryId,
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            self.exchanges
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            let token = if authn_token == AUTHN_ONE {
                AUTHZ_ONE
            } else {
                AUTHZ_TWO
            };
            Ok(AuthorizationToken {
                token: token.to_string(),
                expires_ms: 0,
                acceptable_root_domains: vec!["example.com".to_string()],
            })
        }

        async fn start_auth_session(
            &self,
            _auth_url: &str,
            _client_state: &str,
            _correlation_id: &str,
        ) -> Result<AuthSession, ProtocolError> {
            Err(ProtocolError::internal(
                "the stub only serves authorization exchanges",
            ))
        }

        async fn poll_auth_session(
            &self,
            _auth_url: &str,
            _client_state: &str,
            _session_code: &str,
            _correlation_id: &str,
        ) -> Result<Option<AuthenticationToken>, ProtocolError> {
            Err(ProtocolError::internal(
                "the stub only serves authorization exchanges",
            ))
        }

        async fn exchange_external_token(
            &self,
            _auth_url: &str,
            _token: &str,
            _token_type: &str,
            _correlation_id: &str,
        ) -> Result<AuthenticationToken, ProtocolError> {
            Err(ProtocolError::internal(
                "the stub only serves authorization exchanges",
            ))
        }

        async fn refresh_authentication(
            &self,
            _auth_url: &str,
            _refresh_token: &str,
            _correlation_id: &str,
        ) -> Result<AuthenticationToken, ProtocolError> {
            Err(ProtocolError::internal(
                "the stub only serves authorization exchanges",
            ))
        }

        async fn exchange_for_custom_resource(
            &self,
            _auth_url: &str,
            _authn_token: &str,
            _resource_id: &str,
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            Err(ProtocolError::internal(
                "the stub only serves repository exchanges",
            ))
        }
    }

    async fn authorize(repository: RepositoryId, identity_token: &str) -> String {
        exchange(
            AUTH_URL,
            "alice",
            repository,
            "example.com".to_string(),
            identity_token,
            "",
        )
        .await
        .expect("the stub authorizes")
    }

    let stub = std::sync::Arc::new(StubAuthentication {
        exchanges: std::sync::atomic::AtomicUsize::new(0),
    });
    authentication::add("stub-auth", stub.clone()).expect("registering the stub");

    let repository: RepositoryId = "aabbccdd00112233aabbccdd00112233"
        .parse()
        .expect("a valid repository id");

    assert_eq!(authorize(repository, AUTHN_ONE).await, AUTHZ_ONE);
    assert_eq!(
        authorize(repository, AUTHN_ONE).await,
        AUTHZ_ONE,
        "the same credential reuses the authorization it earned"
    );
    assert_eq!(
        stub.exchanges.load(std::sync::atomic::Ordering::Acquire),
        1,
        "a repeat of the same credential must come from the cache"
    );

    assert_eq!(
        authorize(repository, AUTHN_TWO).await,
        AUTHZ_TWO,
        "a different credential must earn its own authorization"
    );
    assert_eq!(
        stub.exchanges.load(std::sync::atomic::Ordering::Acquire),
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

fn register_delayed(scheme: &str, provider: DelayedAuthentication) -> Arc<DelayedAuthentication> {
    let provider = Arc::new(provider);
    authentication::add(scheme, provider.clone()).expect("register provider");
    provider
}

async fn sf_exchange(auth_url: &str, repository: RepositoryId) -> Result<String, ExchangeError> {
    exchange(
        auth_url,
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
