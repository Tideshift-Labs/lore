// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use chrono::TimeZone;
use chrono::Utc;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_revision::lore::RepositoryId;
use lore_revision::util::time::RetryPolicy;
use lore_server::hooks::Hook;
use lore_server::hooks::HookContext;
use lore_server::hooks::HookError;
use lore_server::hooks::HookFactory;
use lore_server::hooks::HookPoint;
use lore_server::hooks::lorehub_notify::*;
use ring::hmac;

/// A fixed time so payload + `event_id` are deterministic in tests.
fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 24, 12, 34, 56).unwrap()
}

/// Builds a branch-push context with all fields populated.
fn push_context() -> HookContext {
    let partition = RepositoryId::from([0xABu8; 16]);
    let branch = Context::from([0x11u8; 16]);
    let revision = Hash::from([0x22u8; 32]);
    let mut ctx = HookContext::builder()
        .correlation_id("corr-1")
        .hook_point(HookPoint::BranchPush)
        .repository(partition)
        .user("user-sub-123")
        .branch(branch)
        .revision(revision)
        .metadata("client_ip", "203.0.113.7")
        .build();
    ctx.set_revision_number(7);
    ctx
}

#[test]
fn event_type_covers_full_lifecycle_set() {
    assert_eq!(event_type(HookPoint::BranchPush), "branch_push");
    assert_eq!(event_type(HookPoint::BranchCreate), "branch_create");
    assert_eq!(event_type(HookPoint::BranchDelete), "branch_delete");
    assert_eq!(event_type(HookPoint::RepositoryCreate), "repository_create");
    assert_eq!(event_type(HookPoint::Obliterate), "obliterate");
    assert_eq!(event_type(HookPoint::ResourceLock), "lock_acquire");
    assert_eq!(event_type(HookPoint::ResourceUnlock), "lock_release");
    // The hook subscribes to exactly that set.
    assert_eq!(HOOK_POINTS, HookPoint::all());
}

#[test]
fn payload_matches_wp026_contract_shape() {
    let fields = EventFields::from_context(&push_context(), fixed_time());
    let payload = fields.to_payload();
    let obj = payload.as_object().expect("payload is a JSON object");

    // Exactly the contract keys, no more, no less.
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "actor",
            "branch",
            "client_ip",
            "event_id",
            "occurred_at",
            "partition",
            "revision_number",
            "revision_signature",
            "type",
        ]
    );

    assert_eq!(payload["type"], "branch_push");
    assert_eq!(payload["partition"], "ab".repeat(16)); // 0xAB..AB -> 32 hex chars
    assert_eq!(payload["partition"].as_str().unwrap().len(), 32);
    assert_eq!(payload["actor"], "user-sub-123");
    assert_eq!(payload["branch"], "11".repeat(16));
    assert_eq!(payload["revision_signature"], "22".repeat(32));
    assert_eq!(payload["revision_signature"].as_str().unwrap().len(), 64);
    assert_eq!(payload["revision_number"], 7);
    assert_eq!(payload["occurred_at"], "2026-06-24T12:34:56Z");
    assert_eq!(payload["client_ip"], "203.0.113.7");
    assert!(payload["event_id"].is_string());
    assert_eq!(payload["event_id"].as_str().unwrap().len(), 64); // blake3 hex
}

#[test]
fn nullable_fields_serialize_as_json_null() {
    // A repo-level event: no branch, revision, revision_number, client_ip.
    let ctx = HookContext::builder()
        .correlation_id("corr-2")
        .hook_point(HookPoint::RepositoryCreate)
        .repository(RepositoryId::from([0x01u8; 16]))
        .user("creator")
        .build();
    let payload = EventFields::from_context(&ctx, fixed_time()).to_payload();

    assert_eq!(payload["type"], "repository_create");
    assert!(payload["branch"].is_null());
    assert!(payload["revision_signature"].is_null());
    assert!(payload["revision_number"].is_null());
    assert!(payload["client_ip"].is_null());
    assert_eq!(payload["actor"], "creator");
}

#[test]
fn event_id_is_deterministic_and_distinct() {
    let a = EventFields::from_context(&push_context(), fixed_time());
    let b = EventFields::from_context(&push_context(), fixed_time());
    // Same event identity -> same id (idempotency holds across retries).
    assert_eq!(a.event_id(), b.event_id());

    // A different revision -> a different id.
    let mut other = a.clone();
    other.revision_signature = Some("33".repeat(32));
    assert_ne!(a.event_id(), other.event_id());

    // A different occurred_at -> a different id.
    let later = EventFields::from_context(
        &push_context(),
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 34, 57).unwrap(),
    );
    assert_ne!(a.event_id(), later.event_id());
}

/// Builds a lock-acquire context: repository + branch + user + `lock_hash`/
/// `lock_description` metadata, no revision (mirrors what
/// `lock_service.rs::lock_hook_context` builds for a real lock/unlock).
fn lock_context(lock_hash: &str) -> HookContext {
    let partition = RepositoryId::from([0xABu8; 16]);
    let branch = Context::from([0x11u8; 16]);
    HookContext::builder()
        .correlation_id("corr-lock")
        .hook_point(HookPoint::ResourceLock)
        .repository(partition)
        .user("user-sub-123")
        .branch(branch)
        .metadata("lock_hash", lock_hash)
        .metadata("lock_description", "some/path.uasset")
        .build()
}

#[test]
fn lock_hash_disambiguates_event_id_for_same_second_same_repo() {
    // Two distinct locks on the same repo/branch, same occurred_at second: both
    // carry no revision_signature, so without the lock_hash discriminator they'd
    // synthesize the same event_id and the receiver would dedup the second away.
    let a = EventFields::from_context(&lock_context("aaaa"), fixed_time());
    let b = EventFields::from_context(&lock_context("bbbb"), fixed_time());

    assert_eq!(a.partition, b.partition);
    assert_eq!(a.event_type, b.event_type);
    assert_eq!(a.occurred_at, b.occurred_at);
    assert!(a.revision_signature.is_none());
    assert!(b.revision_signature.is_none());
    assert_ne!(a.event_id(), b.event_id());
}

#[test]
fn revision_event_id_unaffected_by_absent_lock_hash() {
    // A revision-producing event carries no lock_hash (None). Folding an empty
    // string in for the discriminator must hash identically to None, so a
    // revision event's id is unchanged by the CR-015 field addition.
    let fields = EventFields::from_context(&push_context(), fixed_time());
    assert!(fields.lock_hash.is_none());

    let mut with_empty_lock_hash = fields.clone();
    with_empty_lock_hash.lock_hash = Some(String::new());
    assert_eq!(fields.event_id(), with_empty_lock_hash.event_id());
}

#[test]
fn lock_payload_matches_contract_shape_and_omits_lock_hash() {
    let fields = EventFields::from_context(&lock_context("deadbeef"), fixed_time());
    let payload = fields.to_payload();
    let obj = payload.as_object().expect("payload is a JSON object");

    // Wire shape is unchanged: the same 9 contract keys, no `lock_hash` key.
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "actor",
            "branch",
            "client_ip",
            "event_id",
            "occurred_at",
            "partition",
            "revision_number",
            "revision_signature",
            "type",
        ]
    );
    assert!(!obj.contains_key("lock_hash"));

    assert_eq!(payload["type"], "lock_acquire");
    assert_eq!(payload["actor"], "user-sub-123");
    assert!(payload["branch"].is_string());
    assert!(payload["revision_signature"].is_null());
    assert!(payload["revision_number"].is_null());
}

#[test]
fn signature_binds_timestamp_and_raw_body() {
    let secret = "shared-secret";
    let timestamp = 1_750_000_000_i64;
    let raw_body = br#"{"hello":"world"}"#;

    let sig = sign_event(secret, timestamp, raw_body);
    assert!(sig.starts_with("sha256="));

    // Recompute the expected MAC independently over `timestamp + "." + raw_body`.
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut input = format!("{timestamp}.").into_bytes();
    input.extend_from_slice(raw_body);
    let expected = format!("sha256={}", hex::encode(hmac::sign(&key, &input).as_ref()));
    assert_eq!(sig, expected);

    // The timestamp is bound in: a different timestamp changes the signature.
    assert_ne!(sig, sign_event(secret, timestamp + 1, raw_body));
    // The body is bound in: a different body changes the signature.
    assert_ne!(sig, sign_event(secret, timestamp, br#"{"hello":"there"}"#));
    // The secret matters.
    assert_ne!(sig, sign_event("other-secret", timestamp, raw_body));
}

#[test]
fn signed_bytes_are_the_bytes_posted() {
    // The signature must be computed over the exact serialized body that the
    // POST sends — recompute end-to-end and confirm they line up.
    let fields = EventFields::from_context(&push_context(), fixed_time());
    let raw_body = serde_json::to_vec(&fields.to_payload()).unwrap();
    let timestamp = fixed_time().timestamp();
    let sig = sign_event("sekret", timestamp, &raw_body);

    let key = hmac::Key::new(hmac::HMAC_SHA256, b"sekret");
    let mut input = format!("{timestamp}.").into_bytes();
    input.extend_from_slice(&raw_body);
    let expected = format!("sha256={}", hex::encode(hmac::sign(&key, &input).as_ref()));
    assert_eq!(sig, expected);
}

#[test]
fn factory_requires_webhook_url_and_secret() {
    let factory = LorehubNotifyHookFactory;

    // Missing both.
    let empty = toml::Value::Table(toml::map::Map::new());
    assert!(matches!(
        factory.create(&empty),
        Err(HookError::ConfigError { .. })
    ));

    // Missing hmac_secret.
    let only_url: toml::Value =
        toml::from_str(r#"webhook_url = "https://example.test/internal/lore-events""#).unwrap();
    assert!(matches!(
        factory.create(&only_url),
        Err(HookError::ConfigError { .. })
    ));

    // Empty hmac_secret is rejected.
    let empty_secret: toml::Value = toml::from_str(
        r#"
        webhook_url = "https://example.test/internal/lore-events"
        hmac_secret = ""
        "#,
    )
    .unwrap();
    assert!(matches!(
        factory.create(&empty_secret),
        Err(HookError::ConfigError { .. })
    ));
}

#[test]
fn factory_builds_hook_from_valid_config() {
    let factory = LorehubNotifyHookFactory;
    let config: toml::Value = toml::from_str(
        r#"
        webhook_url = "https://host.docker.internal:8787/internal/lore-events"
        hmac_secret = "abc123"
        timeout = 5
        "#,
    )
    .unwrap();

    let hook = factory.create(&config).expect("valid config builds a hook");
    assert_eq!(hook.name(), "lorehub_notify");
    assert_eq!(hook.hook_points(), HookPoint::all());
}

#[test]
fn factory_builds_hook_from_valid_retry_table() {
    let factory = LorehubNotifyHookFactory;
    let config: toml::Value = toml::from_str(
        r#"
        webhook_url = "https://host.docker.internal:8787/internal/lore-events"
        hmac_secret = "abc123"

        [retry]
        initial_backoff_ms = 10
        max_backoff_ms = 50
        max_attempts = 4
        "#,
    )
    .unwrap();

    let hook = factory
        .create(&config)
        .expect("a well-formed retry table builds a hook");
    assert_eq!(hook.name(), "lorehub_notify");
}

#[test]
fn factory_rejects_malformed_retry_table() {
    let factory = LorehubNotifyHookFactory;
    // `max_attempts` must be an integer; a string fails RetrySettings deserialization.
    let config: toml::Value = toml::from_str(
        r#"
        webhook_url = "https://example.test/internal/lore-events"
        hmac_secret = "abc123"

        [retry]
        initial_backoff_ms = 200
        max_backoff_ms = 2000
        max_attempts = "two"
        "#,
    )
    .unwrap();

    assert!(matches!(
        factory.create(&config),
        Err(HookError::ConfigError { .. })
    ));
}

/// A near-zero-backoff retry policy so retry-exercising tests don't pay
/// real backoff wall-time. `max_attempts` here is the number of RETRIES
/// (matches `RetrySettings`/`DEFAULT_RETRY_LIMIT`'s convention), so total
/// requests sent on total exhaustion is `max_attempts + 1`.
fn fast_retry_policy(max_attempts: usize) -> RetryPolicy {
    RetryPolicy::builder()
        .with_initial_backoff_millis(1)
        .with_max_backoff_millis(1)
        .with_limit(max_attempts)
        .build()
}

/// Builds a `LorehubNotifyHook` pointed at `webhook_url`, with a client
/// timeout of `client_timeout` (short for the timeout-path test, generous
/// for the others) and the given `retry_policy`.
fn hook_with_url(
    webhook_url: String,
    client_timeout: Duration,
    retry_policy: RetryPolicy,
) -> LorehubNotifyHook {
    LorehubNotifyHook {
        webhook_url,
        hmac_secret: "test-secret".to_string(),
        client: reqwest::Client::builder()
            .timeout(client_timeout)
            .build()
            .expect("build reqwest client"),
        retry_policy,
    }
}

/// Starts a real HTTP server on an ephemeral loopback port that always
/// responds with `status`, so `post_handler`'s `reqwest` client has a real
/// socket to talk to. Mirrors `repository_query.rs`'s
/// `authz_test_support::start_stub_auth_server` bind-then-serve pattern
/// (no drop-rebind TOCTOU, no readiness sleep needed: the socket is in the
/// OS backlog as soon as `bind` returns).
async fn start_stub_receiver(status: axum::http::StatusCode) -> String {
    let (url, _calls) = start_counting_stub_receiver(move |_idx| status).await;
    url
}

/// Starts a real HTTP server on an ephemeral loopback port whose response
/// per request is driven by `respond(call_index)` (0-based), so retry
/// behavior (transient-then-recovers, persistent failure, fail-fast) can
/// be exercised and the number of attempts asserted. Returns the URL and a
/// shared counter of requests received so far.
async fn start_counting_stub_receiver<F>(respond: F) -> (String, Arc<AtomicUsize>)
where
    F: Fn(usize) -> axum::http::StatusCode + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("read local_addr");

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_handler = calls.clone();
    let respond = Arc::new(respond);
    let app = axum::Router::new().route(
        "/internal/lore-events",
        axum::routing::post(move || {
            let calls = calls_for_handler.clone();
            let respond = respond.clone();
            async move {
                let idx = calls.fetch_add(1, Ordering::SeqCst);
                respond(idx)
            }
        }),
    );
    lore_base::lore_spawn!(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{addr}/internal/lore-events"), calls)
}

// `post_handler`'s error-return behavior is the only outcome-classification
// signal observable without reading the OTel counter (see the module-level
// gotcha note below on why the counter itself is left untested at this
// tier). Attempt counts (via `start_counting_stub_receiver`) are the signal
// for the WP-066 Chunk 2 retry behavior itself.

#[tokio::test]
async fn post_handler_succeeds_and_records_success_on_2xx() {
    let url = start_stub_receiver(axum::http::StatusCode::OK).await;
    let hook = hook_with_url(url, Duration::from_secs(5), fast_retry_policy(2));

    let result = hook.post_handler(&push_context()).await;
    assert!(
        result.is_ok(),
        "expected Ok on a 2xx response, got {result:?}"
    );
}

#[tokio::test]
async fn post_handler_recovers_after_transient_5xx_then_succeeds() {
    // 503 for the first 2 requests, 200 on the 3rd: the whole point of
    // WP-066 Chunk 2 is that this now succeeds instead of failing on the
    // first 503.
    const TRANSIENT_FAILURES: usize = 2;
    let (url, calls) = start_counting_stub_receiver(|idx| {
        if idx < TRANSIENT_FAILURES {
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        } else {
            axum::http::StatusCode::OK
        }
    })
    .await;
    let hook = hook_with_url(
        url,
        Duration::from_secs(5),
        fast_retry_policy(TRANSIENT_FAILURES + 1),
    );

    let result = hook.post_handler(&push_context()).await;
    assert!(
        result.is_ok(),
        "expected Ok after recovering from transient 503s, got {result:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        TRANSIENT_FAILURES + 1,
        "stub should have been hit exactly once per failure plus the succeeding attempt"
    );
}

#[tokio::test]
async fn post_handler_retries_429_then_succeeds() {
    // 429 is a distinct predicate from `is_server_error()` in `post_handler`
    // (`status == reqwest::StatusCode::TOO_MANY_REQUESTS`) — cover it
    // separately from the 5xx case rather than assuming the same branch.
    const TRANSIENT_FAILURES: usize = 2;
    let (url, calls) = start_counting_stub_receiver(|idx| {
        if idx < TRANSIENT_FAILURES {
            axum::http::StatusCode::TOO_MANY_REQUESTS
        } else {
            axum::http::StatusCode::OK
        }
    })
    .await;
    let hook = hook_with_url(
        url,
        Duration::from_secs(5),
        fast_retry_policy(TRANSIENT_FAILURES + 1),
    );

    let result = hook.post_handler(&push_context()).await;
    assert!(
        result.is_ok(),
        "expected Ok after recovering from transient 429s, got {result:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        TRANSIENT_FAILURES + 1,
        "stub should have been hit exactly once per 429 plus the succeeding attempt"
    );
}

#[tokio::test]
async fn post_handler_fails_fast_on_4xx_with_no_retry() {
    // A 4xx is a permanent failure (bad signature/shape) and must not
    // consume any of the retry budget.
    let (url, calls) =
        start_counting_stub_receiver(|_idx| axum::http::StatusCode::BAD_REQUEST).await;
    let hook = hook_with_url(url, Duration::from_secs(5), fast_retry_policy(3));

    let err = hook
        .post_handler(&push_context())
        .await
        .expect_err("expected Err on a 400 response");
    assert!(
        format!("{err}").contains("400"),
        "error should surface the receiver's status: {err}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a permanent 4xx must not be retried"
    );
}

#[tokio::test]
async fn post_handler_exhausts_retries_and_errors_on_persistent_5xx() {
    const MAX_RETRIES: usize = 2;
    let (url, calls) =
        start_counting_stub_receiver(|_idx| axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
    let hook = hook_with_url(url, Duration::from_secs(5), fast_retry_policy(MAX_RETRIES));

    let err = hook
        .post_handler(&push_context())
        .await
        .expect_err("expected Err once the retry budget is exhausted");
    assert!(
        format!("{err}").contains("500"),
        "error should surface the receiver's status: {err}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        MAX_RETRIES + 1,
        "should send the initial attempt plus {MAX_RETRIES} retries"
    );
}

#[tokio::test]
async fn post_handler_errors_and_records_transport_error_when_unreachable() {
    // Bind then immediately drop: nothing listens on this port, so the
    // connection is refused (a `transport_error` outcome, distinct from
    // `timeout`). Tiny TOCTOU window (another process could grab the port
    // before we connect) is an accepted, extremely unlikely flake source.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("read local_addr");
    drop(listener);

    let hook = hook_with_url(
        format!("http://{addr}/internal/lore-events"),
        Duration::from_secs(5),
        fast_retry_policy(2),
    );

    let err = hook
        .post_handler(&push_context())
        .await
        .expect_err("expected Err when the receiver is unreachable");
    assert!(
        format!("{err}").contains("post:"),
        "error should be the post-phase error: {err}"
    );
}

#[tokio::test]
async fn factory_built_hook_honors_configured_retry_table_attempt_count() {
    // End-to-end through the real parse path (not a direct struct literal):
    // a `[retry]` table with `max_attempts = 1` against a persistent 500
    // must send exactly 2 requests (1 initial + 1 retry) before erroring.
    let (url, calls) =
        start_counting_stub_receiver(|_idx| axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
    let factory = LorehubNotifyHookFactory;
    let config: toml::Value = toml::from_str(&format!(
        r#"
        webhook_url = "{url}"
        hmac_secret = "abc123"

        [retry]
        initial_backoff_ms = 1
        max_backoff_ms = 1
        max_attempts = 1
        "#,
    ))
    .unwrap();
    let hook = factory
        .create(&config)
        .expect("a well-formed retry table builds a hook");

    let err = hook
        .post_handler(&push_context())
        .await
        .expect_err("persistent 500 should exhaust the configured retry budget");
    assert!(format!("{err}").contains("500"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "configured max_attempts = 1 retry -> 2 total requests"
    );
}

#[tokio::test]
async fn factory_built_hook_uses_default_retry_policy_when_retry_table_omitted() {
    // No `[retry]` table -> DEFAULT_RETRY_LIMIT retries against a
    // persistent 500 must send DEFAULT_RETRY_LIMIT + 1 total requests.
    // Uses the real default backoff (not near-zero), so this test pays a
    // little real wall-clock time (well under a second) — the point is to
    // prove the factory's omitted-`[retry]` path, not just our own
    // hardcoded expectation of the constants.
    let (url, calls) =
        start_counting_stub_receiver(|_idx| axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
    let factory = LorehubNotifyHookFactory;
    let config: toml::Value = toml::from_str(&format!(
        r#"
        webhook_url = "{url}"
        hmac_secret = "abc123"
        "#,
    ))
    .unwrap();
    let hook = factory
        .create(&config)
        .expect("config without a retry table builds a hook");

    let err = hook
        .post_handler(&push_context())
        .await
        .expect_err("persistent 500 should exhaust the default retry budget");
    assert!(format!("{err}").contains("500"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        DEFAULT_RETRY_LIMIT + 1,
        "default policy is {DEFAULT_RETRY_LIMIT} retries -> {} total requests",
        DEFAULT_RETRY_LIMIT + 1
    );
}

/// `post_handler` classifies a failed POST as `"timeout"` vs
/// `"transport_error"` purely on `reqwest::Error::is_timeout()` — confirm
/// that predicate actually distinguishes a client-side timeout from a
/// connection refusal on this reqwest version, since that classification
/// itself is only observable through the `OTel` counter label (untestable
/// here, see the gotcha note below), not through `post_handler`'s return
/// value.
#[tokio::test]
async fn reqwest_is_timeout_distinguishes_timeout_from_connection_refused() {
    // Connection refused: nobody listens.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let refused_addr = listener.local_addr().expect("read local_addr");
    drop(listener);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let refused_err = client
        .get(format!("http://{refused_addr}/"))
        .send()
        .await
        .expect_err("connection should be refused");
    assert!(
        !refused_err.is_timeout(),
        "a connection-refused error must not read as a timeout"
    );

    // Client-side timeout: something accepts the connection and holds it
    // open, but never writes a response.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let hung_addr = listener.local_addr().expect("read local_addr");
    lore_base::lore_spawn!(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket); // keep the connection open; never respond
        }
    });

    let timeout_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()
        .expect("build reqwest client");
    let timeout_err = timeout_client
        .get(format!("http://{hung_addr}/"))
        .send()
        .await
        .expect_err("request should time out");
    assert!(
        timeout_err.is_timeout(),
        "a held-open, non-responding connection must read as a timeout"
    );
}

#[test]
fn factory_rejects_non_integer_timeout() {
    let factory = LorehubNotifyHookFactory;
    let config: toml::Value = toml::from_str(
        r#"
        webhook_url = "https://example.test/internal/lore-events"
        hmac_secret = "abc123"
        timeout = "soon"
        "#,
    )
    .unwrap();
    assert!(matches!(
        factory.create(&config),
        Err(HookError::ConfigError { .. })
    ));
}

#[test]
fn factory_rejects_zero_timeout() {
    let factory = LorehubNotifyHookFactory;
    let config: toml::Value = toml::from_str(
        r#"
        webhook_url = "https://example.test/internal/lore-events"
        hmac_secret = "abc123"
        timeout = 0
        "#,
    )
    .unwrap();
    assert!(matches!(
        factory.create(&config),
        Err(HookError::ConfigError { .. })
    ));
    // A positive timeout still builds fine — already covered by
    // `factory_builds_hook_from_valid_config` (`timeout = 5`).
}
