// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use base64::prelude::BASE64_STANDARD;
use base64::prelude::Engine as _;
use lore_credential::IdentityToken;
use lore_credential::token_store::AuthenticationRefreshCommit;
use lore_credential::token_store::RemoteIdentity;
use lore_credential::token_store::TokenMap;
use lore_credential::token_store::acquire_authentication_refresh;
use lore_credential::token_store::load_refresh_token;
use lore_credential::token_store::load_user_token;
use lore_credential::token_store::reset_tokens;
use lore_credential::token_store::store_authentication_token;
use lore_credential::token_store::store_refresh_token;
use lore_credential::token_store::store_user_token;
use lore_credential::token_store::test_util::clear_encryption_cache;
use lore_credential::token_store::test_util::encryption_key_from_stored;
use lore_credential::token_store::test_util::generate_encryption_key;
use lore_credential::token_store::test_util::is_entry_for_auth_url;
use lore_credential::token_store::test_util::open_token;
use lore_credential::token_store::test_util::seal_token;
use lore_credential::token_store::test_util::single_nonce_sequence;
use lore_credential::token_store::test_util::split_remote_resource;
use lore_credential::token_store::test_util::store_cached_token_map;
use lore_credential::token_store::test_util::token_map_path;
use lore_credential::token_store::tokens_only_for_recipient_domain;
use lore_credential::token_store::vulnerable_all_tokens;
use ring::aead::AES_256_GCM;
use ring::aead::NONCE_LEN;
use ring::aead::NonceSequence;

#[test]
fn refresh_token_serde_default_none() {
    // Old store format without refresh_token field
    let toml_str = r#"
user_id = "user-1"
token = "encrypted-token"
acceptable_root_domains = ["example.com"]
"#;
    let token: IdentityToken = toml::from_str(toml_str).unwrap();
    assert!(token.refresh_token().is_none());
    assert_eq!(token.user_id(), "user-1");
    assert_eq!(token.token(), "encrypted-token");
}

#[test]
fn refresh_token_serde_roundtrip() {
    let token = IdentityToken::new(
        "user-1",
        "encrypted-auth",
        vec!["example.com".into()],
        Some("encrypted-refresh".into()),
    );
    let serialized = toml::to_string_pretty(&token).unwrap();
    let deserialized: IdentityToken = toml::from_str(&serialized).unwrap();
    assert_eq!(deserialized.refresh_token(), Some("encrypted-refresh"));
    assert_eq!(deserialized.user_id(), "user-1");
}

#[test]
fn identity_token_without_refresh_backward_compat() {
    // Simulates an old store file structure
    let toml_str = r#"
[[remotes]]
remote = "https://auth.example.com"

[[remotes.token]]
user_id = "alice"
token = "tok-a"
acceptable_root_domains = ["example.com"]

[[remotes.token]]
user_id = "bob"
token = "tok-b"
"#;
    let map: TokenMap = toml::from_str(toml_str).unwrap();
    assert_eq!(map.remotes().len(), 1);
    assert_eq!(map.remotes()[0].tokens().len(), 2);
    assert!(map.remotes()[0].tokens()[0].refresh_token().is_none());
    assert!(map.remotes()[0].tokens()[1].refresh_token().is_none());
}

#[test]
fn token_map_with_refresh_token_roundtrip() {
    let map = TokenMap::new(vec![RemoteIdentity::new(
        "https://auth.example.com",
        vec![IdentityToken::new(
            "alice",
            "auth-tok",
            vec!["example.com".into()],
            Some("refresh-tok".into()),
        )],
    )]);
    let serialized = toml::to_string_pretty(&map).unwrap();
    let deserialized: TokenMap = toml::from_str(&serialized).unwrap();
    assert_eq!(
        deserialized.remotes()[0].tokens()[0].refresh_token(),
        Some("refresh-tok")
    );
}

#[test]
fn encryption_key_from_stored_accepts_a_bare_key() {
    let key = generate_encryption_key().unwrap();
    assert_eq!(key.len(), AES_256_GCM.key_len());
    assert_eq!(encryption_key_from_stored(&key).as_ref(), Some(&key));
}

#[test]
fn encryption_key_from_stored_rejects_malformed() {
    assert!(encryption_key_from_stored(&[]).is_none());
    assert!(encryption_key_from_stored(&[0u8; 16]).is_none());
    // The layout earlier versions wrote: a nonce counter ahead of the key.
    assert!(encryption_key_from_stored(&[0u8; 4 + 32]).is_none());
}

#[test]
fn seal_and_open_token_round_trip() {
    let key = generate_encryption_key().unwrap();
    let sealed = seal_token(&key, "a-user-token").unwrap();
    assert_eq!(open_token(&key, &sealed).unwrap(), "a-user-token");
}

#[test]
fn seal_token_prefixes_the_nonce() {
    let key = generate_encryption_key().unwrap();
    let blob = BASE64_STANDARD
        .decode(seal_token(&key, "a-user-token").unwrap())
        .unwrap();
    assert_eq!(blob.len(), NONCE_LEN + "a-user-token".len() + 16);
}

#[test]
fn seal_token_draws_a_fresh_nonce_each_time() {
    let key = generate_encryption_key().unwrap();
    let first = seal_token(&key, "a-user-token").unwrap();
    let second = seal_token(&key, "a-user-token").unwrap();
    assert_ne!(first, second);
}

#[test]
fn open_token_rejects_short_blobs() {
    let key = generate_encryption_key().unwrap();
    let short = BASE64_STANDARD.encode([0u8; NONCE_LEN - 1]);
    assert!(open_token(&key, &short).is_err());
}

#[test]
fn open_token_rejects_a_foreign_key() {
    let sealed = seal_token(&generate_encryption_key().unwrap(), "a-user-token").unwrap();
    assert!(open_token(&generate_encryption_key().unwrap(), &sealed).is_err());
}

#[test]
fn single_nonce_sequence_refuses_second_advance() {
    let mut sequence = single_nonce_sequence([0u8; NONCE_LEN]);
    assert!(sequence.advance().is_ok());
    assert!(sequence.advance().is_err());
}

#[test]
fn split_remote_resource_new_format() {
    let (auth, resource) =
        split_remote_resource("https://auth.example.com/00112233445566778899aabbccddeeff");
    assert_eq!(auth, "https://auth.example.com");
    assert_eq!(resource, "00112233445566778899aabbccddeeff");
}

#[test]
fn split_remote_resource_legacy_format() {
    let (auth, resource) =
        split_remote_resource("https://auth.example.com/urc-00112233445566778899aabbccddeeff");
    assert_eq!(auth, "https://auth.example.com");
    assert_eq!(resource, "urc-00112233445566778899aabbccddeeff");
}

#[test]
fn split_remote_resource_no_resource() {
    let (auth, resource) = split_remote_resource("https://auth.example.com");
    assert_eq!(auth, "https://auth.example.com");
    assert!(resource.is_empty());
}

#[test]
fn split_remote_resource_scheme_with_hostname() {
    let (auth, resource) =
        split_remote_resource("ucs-auth://auth.example.com/aabbccdd00112233aabbccdd00112233");
    assert_eq!(auth, "ucs-auth://auth.example.com");
    assert_eq!(resource, "aabbccdd00112233aabbccdd00112233");
}

#[test]
fn is_entry_for_auth_url_base() {
    assert!(is_entry_for_auth_url(
        "https://auth.example.com",
        "https://auth.example.com"
    ));
}

#[test]
fn is_entry_for_auth_url_new_format() {
    assert!(is_entry_for_auth_url(
        "https://auth.example.com/00112233445566778899aabbccddeeff",
        "https://auth.example.com"
    ));
}

#[test]
fn is_entry_for_auth_url_legacy_format() {
    assert!(is_entry_for_auth_url(
        "https://auth.example.com/urc-00112233445566778899aabbccddeeff",
        "https://auth.example.com"
    ));
}

#[test]
fn is_entry_for_auth_url_different_host() {
    assert!(!is_entry_for_auth_url(
        "https://other.example.com/00112233445566778899aabbccddeeff",
        "https://auth.example.com"
    ));
}

#[test]
fn is_entry_for_auth_url_non_hex_suffix() {
    assert!(!is_entry_for_auth_url(
        "https://auth.example.com/not-a-resource",
        "https://auth.example.com"
    ));
}

/// A supplied token is passed through untouched, so it need not be a JWT.
const SUPPLIED_TOKEN: &str = "supplied-authentication-token";

#[tokio::test]
async fn supplied_identity_token_is_used_without_the_store() {
    // No auth endpoint and no store entry: the supplied token is returned on
    // its own, where a store read would report TokenNotFound.
    let token = load_user_token(
        "",
        "alice",
        tokens_only_for_recipient_domain("nowhere.example".to_string()),
        SUPPLIED_TOKEN,
        "",
    )
    .await
    .expect("the supplied token is used as given");
    assert_eq!(token, SUPPLIED_TOKEN);

    // An access token alongside it changes nothing: the identity token is
    // still the authentication token to use.
    let token = load_user_token(
        "",
        "alice",
        tokens_only_for_recipient_domain("nowhere.example".to_string()),
        SUPPLIED_TOKEN,
        "supplied-access-token",
    )
    .await
    .expect("the supplied token is used as given");
    assert_eq!(token, SUPPLIED_TOKEN);
}

#[tokio::test]
async fn no_supplied_token_reads_the_store() {
    // Nothing supplied, so this is a plain store read, which has no entry
    // for an empty endpoint.
    let result = load_user_token(
        "",
        "alice",
        tokens_only_for_recipient_domain("nowhere.example".to_string()),
        "",
        "",
    )
    .await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// FORK-LOCAL (Tideshift, CR-020): refresh-credential pairs and the refresh
// lease. Moved from the inline `src/token_store.rs` tests when the crate's lib
// test harness was turned off. The store seams they need are in
// `token_store::test_util`.
// ---------------------------------------------------------------------------

const REFRESH_AUTH_ENDPOINT: &str = "https://refresh.auth.example.com";
static REFRESH_TEST_MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static REFRESH_TEST_PATH: OnceLock<PathBuf> = OnceLock::new();

async fn refresh_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    REFRESH_TEST_MUTEX
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn setup_refresh_test() {
    let path = REFRESH_TEST_PATH.get_or_init(|| {
        std::env::temp_dir().join(format!("lore-cr020-token-store-{}", std::process::id()))
    });
    unsafe {
        std::env::set_var("LORE_AUTH_PATH", path);
        std::env::set_var("LORE_AUTH_STORE", "fallback");
    }
    clear_encryption_cache().await;
    reset_tokens().await.expect("reset test token store");
}

async fn store_refresh_pair(identity: &str, token: &str, refresh_token: &str) {
    store_user_token(REFRESH_AUTH_ENDPOINT, identity, token, vec![])
        .await
        .expect("store authentication token");
    store_refresh_token(REFRESH_AUTH_ENDPOINT, identity, refresh_token)
        .await
        .expect("store refresh credential");
}

fn replace_token_file_with_directory() -> PathBuf {
    let path = token_map_path(false).expect("token map path");
    std::fs::remove_file(&path).expect("remove token map file");
    std::fs::create_dir(&path).expect("replace token map file with directory");
    path
}

async fn restore_token_file(path: &Path) {
    std::fs::remove_dir(path).expect("remove token map failure directory");
    store_cached_token_map()
        .await
        .expect("restore token map file");
}

/// The caller is working from tokens they supplied, so the store is off
/// limits: an access token with no identity token beside it reports
/// `TokenNotFound` rather than reading whichever identity happens to be
/// stored. Proven against a store that does hold a matching token, so a
/// regression to the fallback would be visible here.
///
/// Redirects the store to a temp directory and takes the file fallback for
/// the encryption key, so the developer's real keyring and tokens are never
/// touched.
#[tokio::test]
async fn access_token_alone_does_not_fall_back_to_the_store() {
    let _guard = refresh_test_guard().await;
    const AUTH_URL: &str = "ucs-auth://store-fallback.test.invalid";
    let store_dir = std::env::temp_dir().join("lore-token-store-fallback-test");
    std::fs::create_dir_all(&store_dir).expect("a temp store directory");
    // SAFETY: single-threaded setup for this test; no other test in this
    // binary reads the token store.
    unsafe {
        std::env::set_var("LORE_AUTH_PATH", store_dir.display().to_string());
        std::env::set_var("LORE_AUTH_STORE", "fallback");
    }
    clear_encryption_cache().await;

    store_user_token(
        AUTH_URL,
        "alice",
        "stored-token",
        vec!["test.invalid".to_string()],
    )
    .await
    .expect("storing a token");

    // Nothing supplied: the stored token is found, so the store really does
    // answer for this identity.
    let stored = load_user_token(
        AUTH_URL,
        "alice",
        tokens_only_for_recipient_domain("test.invalid".to_string()),
        "",
        "",
    )
    .await
    .expect("the stored token is found");
    assert_eq!(stored, "stored-token");

    // An access token supplied instead: the same lookup now refuses.
    let refused = load_user_token(
        AUTH_URL,
        "alice",
        tokens_only_for_recipient_domain("test.invalid".to_string()),
        "",
        "supplied-access-token",
    )
    .await;
    assert!(
        refused.is_err(),
        "an access token must not fall back to the stored identity"
    );

    let _ = std::fs::remove_dir_all(&store_dir);
}
#[tokio::test]
async fn store_authentication_token_stores_supplied_pair() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;

    store_authentication_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        "authn-initial",
        vec![],
        Some("refresh-initial"),
    )
    .await
    .expect("store initial authentication pair");

    assert_eq!(
        load_user_token(
            REFRESH_AUTH_ENDPOINT,
            "alice",
            vulnerable_all_tokens(),
            "",
            "",
        )
        .await
        .expect("load initial authentication token"),
        "authn-initial"
    );
    assert_eq!(
        load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice")
            .await
            .expect("load initial refresh credential"),
        "refresh-initial"
    );
}

#[tokio::test]
async fn store_authentication_token_replaces_both_supplied_credentials() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_authentication_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        "authn-old",
        vec![],
        Some("refresh-old"),
    )
    .await
    .expect("store old authentication pair");

    store_authentication_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        "authn-new",
        vec![],
        Some("refresh-new"),
    )
    .await
    .expect("replace authentication pair");

    assert_eq!(
        load_user_token(
            REFRESH_AUTH_ENDPOINT,
            "alice",
            vulnerable_all_tokens(),
            "",
            "",
        )
        .await
        .expect("load replaced authentication token"),
        "authn-new"
    );
    assert_eq!(
        load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice")
            .await
            .expect("load replaced refresh credential"),
        "refresh-new"
    );
}

#[tokio::test]
async fn store_authentication_token_without_refresh_preserves_existing_credential() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_authentication_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        "authn-old",
        vec![],
        Some("refresh-old"),
    )
    .await
    .expect("store old authentication pair");

    store_authentication_token(REFRESH_AUTH_ENDPOINT, "alice", "authn-new", vec![], None)
        .await
        .expect("replace authentication token");

    assert_eq!(
        load_user_token(
            REFRESH_AUTH_ENDPOINT,
            "alice",
            vulnerable_all_tokens(),
            "",
            "",
        )
        .await
        .expect("load replaced authentication token"),
        "authn-new"
    );
    assert_eq!(
        load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice")
            .await
            .expect("load preserved refresh credential"),
        "refresh-old"
    );
}

#[tokio::test]
async fn failed_authentication_pair_write_keeps_previous_cached_pair() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_authentication_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        "authn-old",
        vec![],
        Some("refresh-old"),
    )
    .await
    .expect("store old authentication pair");
    let path = replace_token_file_with_directory();

    let write_result = store_authentication_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        "authn-new",
        vec![],
        Some("refresh-new"),
    )
    .await;
    let cached_authn = load_user_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        vulnerable_all_tokens(),
        "",
        "",
    )
    .await;
    let cached_refresh = load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice").await;
    restore_token_file(&path).await;

    assert!(
        write_result.is_err(),
        "directory target accepted token write"
    );
    assert_eq!(
        cached_authn.expect("load cached authentication token"),
        "authn-old"
    );
    assert_eq!(
        cached_refresh.expect("load cached refresh credential"),
        "refresh-old"
    );
}

#[tokio::test]
async fn failed_refresh_commit_keeps_previous_cached_pair() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;
    let lease = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire refresh lease");
    let path = replace_token_file_with_directory();

    let write_result = lease.commit("authn-new", Some("refresh-new"), vec![]).await;
    let cached_authn = load_user_token(
        REFRESH_AUTH_ENDPOINT,
        "alice",
        vulnerable_all_tokens(),
        "",
        "",
    )
    .await;
    let cached_refresh = load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice").await;
    restore_token_file(&path).await;

    assert!(
        write_result.is_err(),
        "directory target accepted token write"
    );
    assert_eq!(
        cached_authn.expect("load cached authentication token"),
        "authn-old"
    );
    assert_eq!(
        cached_refresh.expect("load cached refresh credential"),
        "refresh-old"
    );
}

#[tokio::test]
async fn authentication_refresh_lease_snapshots_current_pair() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;

    let lease = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire refresh lease");

    assert_eq!(
        (
            lease.snapshot().token.as_str(),
            lease.snapshot().refresh_token.as_str(),
        ),
        ("authn-old", "refresh-old")
    );
}

#[tokio::test]
async fn authentication_refresh_commit_replaces_pair_atomically() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;
    let lease = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire refresh lease");

    let result = lease
        .commit(
            "authn-new",
            Some("refresh-new"),
            vec!["repo.example.com".to_string()],
        )
        .await
        .expect("commit refreshed pair");

    assert_eq!(result, AuthenticationRefreshCommit::Stored);
    assert_eq!(
        load_user_token(
            REFRESH_AUTH_ENDPOINT,
            "alice",
            vulnerable_all_tokens(),
            "",
            "",
        )
        .await
        .expect("load authentication token"),
        "authn-new"
    );
    assert_eq!(
        load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice")
            .await
            .expect("load refresh credential"),
        "refresh-new"
    );
}

#[tokio::test]
async fn authentication_refresh_commit_preserves_credential_when_replacement_absent() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;
    let lease = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire refresh lease");

    lease
        .commit("authn-new", None, vec![])
        .await
        .expect("commit refreshed token");

    assert_eq!(
        load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice")
            .await
            .expect("load refresh credential"),
        "refresh-old"
    );
}

#[tokio::test]
async fn authentication_refresh_commit_does_not_overwrite_intervening_login() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;
    let lease = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire refresh lease");
    store_user_token(REFRESH_AUTH_ENDPOINT, "alice", "authn-from-login", vec![])
        .await
        .expect("store intervening login");

    let result = lease
        .commit("authn-from-refresh", Some("refresh-new"), vec![])
        .await
        .expect("compare and commit");

    assert_eq!(
        result,
        AuthenticationRefreshCommit::Superseded {
            token: "authn-from-login".to_string()
        }
    );
    assert_eq!(
        load_refresh_token(REFRESH_AUTH_ENDPOINT, "alice")
            .await
            .expect("load refresh credential"),
        "refresh-old"
    );
}

#[tokio::test]
async fn authentication_refresh_lease_serializes_same_identity_and_rereads_winner() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;
    let winner = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire winner lease");

    #[allow(clippy::disallowed_methods)]
    let waiter = tokio::spawn(async {
        acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
            .await
            .expect("acquire waiter lease")
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!waiter.is_finished(), "same identity did not serialize");

    winner
        .commit("authn-new", Some("refresh-new"), vec![])
        .await
        .expect("commit winner pair");
    let waiter = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("waiter remained blocked")
        .expect("waiter task failed");

    assert_eq!(
        (
            waiter.snapshot().token.as_str(),
            waiter.snapshot().refresh_token.as_str(),
        ),
        ("authn-new", "refresh-new")
    );
}

#[tokio::test]
async fn authentication_refresh_lease_does_not_cross_identity_scope() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-a", "refresh-a").await;
    store_refresh_pair("bob", "authn-b", "refresh-b").await;
    let alice = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire alice lease");

    let bob = tokio::time::timeout(
        Duration::from_secs(5),
        acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "bob"),
    )
    .await
    .expect("bob blocked on alice lease")
    .expect("acquire bob lease");

    assert_eq!(bob.snapshot().token, "authn-b");
    drop(alice);
}

#[tokio::test]
async fn authentication_refresh_lease_drop_releases_same_identity() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;
    let lease = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("acquire first lease");

    drop(lease);

    tokio::time::timeout(
        Duration::from_secs(5),
        acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice"),
    )
    .await
    .expect("lease remained held after drop")
    .expect("acquire replacement lease");
}

#[tokio::test]
async fn authentication_refresh_lease_releases_after_process_exit() {
    let _guard = refresh_test_guard().await;
    setup_refresh_test().await;
    store_refresh_pair("alice", "authn-old", "refresh-old").await;
    let executable = std::env::current_exe().expect("current test executable");
    let auth_path = REFRESH_TEST_PATH.get().expect("refresh test path").clone();

    #[allow(clippy::disallowed_methods)]
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new(executable)
            .arg("--exact")
            .arg("token_store::authentication_refresh_lease_child_process_holder")
            .arg("--nocapture")
            .env("LORE_AUTH_PATH", auth_path)
            .env("LORE_AUTH_STORE", "fallback")
            .env("CR020_REFRESH_CHILD", "1")
            .status()
            .expect("run child refresh holder")
    })
    .await
    .expect("join child process");
    assert!(status.success(), "child refresh holder failed: {status}");

    tokio::time::timeout(
        Duration::from_secs(5),
        acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice"),
    )
    .await
    .expect("lease remained held after child process exited")
    .expect("acquire lease after child exit");
}

#[tokio::test]
#[allow(clippy::disallowed_methods)]
async fn authentication_refresh_lease_child_process_holder() {
    if std::env::var("CR020_REFRESH_CHILD").as_deref() != Ok("1") {
        return;
    }

    let _lease = acquire_authentication_refresh(REFRESH_AUTH_ENDPOINT, "alice")
        .await
        .expect("child acquires refresh lease");
    std::process::exit(0);
}
