// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `lorehub_notify` — a post-commit hook that notifies the Lorehub platform of writes.
//!
//! Lorehub (the hosting platform built on top of Lore) needs to learn about every
//! write so it can drive activity feeds, "last pushed N ago", audit trails, and
//! webhook fan-out. loreserver itself emits no HTTP webhooks — its lifecycle hooks
//! are compile-in Rust [`Hook`] traits — so this module bridges the gap: after a
//! write commits, it builds a small JSON event, signs it with HMAC-SHA256, and
//! POSTs it to a configured Lorehub receiver (`POST /internal/lore-events`).
//!
//! # Why `post_handler`
//!
//! This is an **after-commit, non-veto, outbound-I/O** notification, so it lives in
//! [`Hook::post_handler`] — spawned in its own tokio task, bounded by the dispatcher's
//! 30 s post-handler timeout, and unable to fail the operation. The synchronous
//! `pre_handler` (200 ms budget, can veto) is the wrong phase: a network round-trip
//! does not fit its budget, and gate-on-push policy belongs at token-mint time, not
//! here. Delivery is **at-least-once**: the POST is retried a bounded number of times
//! on a transient failure (transport error/timeout or 5xx/429) with backoff (WP-066
//! option C), but there is no persistent outbox — a loreserver crash or an outage
//! longer than the retry budget still drops the event. The receiver is idempotent on
//! `event_id` (synthesized deterministically), so a retried POST that already landed
//! is a no-op.
//!
//! # This hook is deliberately not routed through the CR-032 outbox
//!
//! A Postgres-mode cell now has a durable outbox and a relay
//! (`crate::event_relay`), so "there is no persistent outbox" above is a
//! statement about **this** path, not about the process. Keeping the two
//! separate is the design, not an omission (WP-119 Phase 7):
//!
//! * An outbox row is a **cell-internal invalidation** addressed to the
//!   notification plane. It carries a repository generation and an aggregate
//!   version, and it exists so a receiver can tell what it has already seen.
//!   It is **not** a platform audit record: it has no actor, no client IP, no
//!   occurred-at wall clock, and no HMAC — every field the Lorehub receiver
//!   authenticates and files. Reading a row as an audit event would fabricate
//!   the four fields it does not contain.
//! * This hook is a **signed, actor-attributed HTTP POST** to a platform
//!   endpoint outside the cell. Its integrity comes from the MAC over the exact
//!   bytes sent, which is a property of this hook and not of the relay.
//!
//! The residual is therefore real and accepted: a crash between the commit and
//! this hook's POST loses the notification, and nothing replays it. That is the
//! same at-least-once-with-a-hole the retry paragraph above describes, and it
//! stays until a hook-outbox package owns durable delivery for the signed
//! platform contract specifically. Do not close it by emitting an outbox row
//! instead — that changes what the platform is told, not how reliably it is
//! told.
//!
//! # The event contract (pinned by Lorehub WP-026)
//!
//! A single signed JSON POST per event:
//!
//! ```json
//! {
//!   "event_id":           "<blake3(partition|type|revision_signature|occurred_at)>",
//!   "type":               "branch_push",
//!   "partition":          "0194b726b34e72b0b45550b88a967076",
//!   "actor":              "<jwt sub>",
//!   "branch":             "<branch id, 32-hex>",
//!   "revision_signature": "<64-hex>",
//!   "revision_number":    7,
//!   "occurred_at":        "2026-06-24T12:34:56Z",
//!   "client_ip":          "203.0.113.7"
//! }
//! ```
//!
//! Nullable fields (`branch`, `revision_signature`, `revision_number`, `client_ip`,
//! and `actor` when no user is present) are serialized as JSON `null`.
//!
//! Authentication is **HMAC over the body** (loreserver holds no Lorehub session).
//! Headers:
//!
//! - `X-Lorehub-Timestamp: <unix-seconds>`
//! - `X-Lorehub-Signature: sha256=<hex( HMAC_SHA256(secret, timestamp + "." + raw_body) )>`
//!
//! The receiver recomputes the MAC over the **raw body** with the timestamp bound in,
//! constant-time compares, and rejects a clock skew greater than 300 s. We therefore
//! POST the exact bytes we signed (`reqwest::body`, never re-serialize).
//!
//! # Configuration
//!
//! ```toml
//! [hooks.lorehub_notify]
//! enabled     = true
//! webhook_url = "https://host.docker.internal:8787/internal/lore-events"
//! hmac_secret = "<LH_LORE_EVENTS_SECRET>"
//! timeout     = 5            # per-attempt HTTP timeout, seconds (optional, default 5)
//!
//! # Optional bounded retry (WP-066 option C). Omitted → default: 2 retries,
//! # 200 ms→2 s backoff. Keep timeout * (max_attempts + 1) + backoffs under 30 s.
//! [hooks.lorehub_notify.retry]
//! initial_backoff_ms = 200
//! max_backoff_ms     = 2000
//! max_attempts       = 2      # number of RETRIES (2 → up to 3 total sends)
//! # jitter           = 0.1    # optional
//! ```

use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use chrono::SecondsFormat;
use chrono::Utc;
use lore_revision::util::time::RetryPolicy;
use lore_revision::util::time::RetrySettings;
use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use ring::hmac;
use serde_json::Value;
use serde_json::json;
use tracing::debug;

use crate::hooks::Hook;
use crate::hooks::HookContext;
use crate::hooks::HookError;
use crate::hooks::HookFactory;
use crate::hooks::HookPoint;
use crate::hooks::HookRegistrationContext;
use crate::hooks::HookRegistry;

/// Configuration section name (`[hooks.lorehub_notify]`) and hook identity.
const HOOK_NAME: &str = "lorehub_notify";

/// Default per-request HTTP timeout (seconds) when `timeout` is omitted. Applies to
/// EACH attempt; with the default retry policy the worst-case total (attempts +
/// backoff sleeps) must stay under the dispatcher's 30 s post-handler timeout, so
/// this is 5 s (5 + 0.2 + 5 + 0.4 + 5 ≈ 16 s for 3 attempts), not the old 10 s.
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Default retry policy for the POST when `[hooks.lorehub_notify.retry]` is omitted.
/// `LIMIT` is the number of RETRIES (so 2 → up to 3 total sends). Catches the common
/// transient failure (api restart, brief blip / 5xx) without persistence (WP-066
/// option C). Keep `timeout * (LIMIT + 1) + backoffs` under the 30 s post-handler cap.
#[lore_macro::test_pub]
const DEFAULT_RETRY_LIMIT: usize = 2;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS: u64 = 200;
const DEFAULT_RETRY_MAX_BACKOFF_MS: u64 = 2_000;

/// The lifecycle points this hook fires for — the full write set
/// (`BranchPush`/`BranchCreate`/`BranchDelete`/`RepositoryCreate`/`Obliterate`) plus
/// lock/unlock (`ResourceLock`/`ResourceUnlock`, CR-015).
#[lore_macro::test_pub]
const HOOK_POINTS: &[HookPoint] = &[
    HookPoint::BranchPush,
    HookPoint::BranchCreate,
    HookPoint::BranchDelete,
    HookPoint::RepositoryCreate,
    HookPoint::Obliterate,
    HookPoint::ResourceLock,
    HookPoint::ResourceUnlock,
];

/// Maps a [`HookPoint`] to the Lorehub event-type string in the contract.
///
/// The `lock_acquire`/`lock_release` strings are the contract Lorehub's
/// `/internal/lore-events` receiver matches on (WP-065) — keep them in lockstep.
#[lore_macro::test_pub]
fn event_type(point: HookPoint) -> &'static str {
    match point {
        HookPoint::BranchPush => "branch_push",
        HookPoint::BranchCreate => "branch_create",
        HookPoint::BranchDelete => "branch_delete",
        HookPoint::RepositoryCreate => "repository_create",
        HookPoint::Obliterate => "obliterate",
        HookPoint::ResourceLock => "lock_acquire",
        HookPoint::ResourceUnlock => "lock_release",
    }
}

/// The flattened event fields extracted from a [`HookContext`], ready to be
/// rendered into the signed JSON payload. Split out from I/O so the payload
/// shape + signature can be unit-tested without a live receiver.
#[lore_macro::test_pub]
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventFields {
    event_type: &'static str,
    /// Repository id as canonical 32-hex (the partition).
    partition: String,
    /// The pushing actor (JWT `sub`); `None` when no user is on the context.
    actor: Option<String>,
    /// Branch id as 32-hex; `None` for repo-level events.
    branch: Option<String>,
    /// Revision signature as 64-hex; `None` when the op carries no revision.
    revision_signature: Option<String>,
    revision_number: Option<u64>,
    /// loreserver clock, RFC 3339 with `Z` suffix and second precision.
    occurred_at: String,
    /// Originating client IP, from `HookContext` metadata; `None` when absent.
    client_ip: Option<String>,
    /// The first locked/unlocked resource's hash (hex), from `HookContext`
    /// metadata on a `lock_acquire`/`lock_release` event; `None` otherwise.
    /// Folded into [`Self::event_id`] so two distinct locks in the same second on
    /// the same repo don't collide (a lock carries no `revision_signature`). Not
    /// serialized onto the wire — the payload shape is unchanged (WP-065 reads
    /// only the partition).
    lock_hash: Option<String>,
}

impl EventFields {
    /// Extracts the contract fields from a hook context, stamping `occurred_at`
    /// with the provided time (injected so tests are deterministic).
    #[lore_macro::test_pub]
    fn from_context(ctx: &HookContext, occurred_at: chrono::DateTime<Utc>) -> Self {
        Self {
            event_type: event_type(ctx.hook_point()),
            partition: ctx.repository().to_string(),
            actor: ctx.user().map(str::to_string),
            branch: ctx.branch().map(|b| b.to_string()),
            revision_signature: ctx.revision().map(|r| r.to_string()),
            revision_number: ctx.revision_number(),
            occurred_at: occurred_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            client_ip: ctx.get_metadata("client_ip").map(str::to_string),
            lock_hash: ctx.get_metadata("lock_hash").map(str::to_string),
        }
    }

    /// Synthesizes the deterministic idempotency key
    /// `blake3(partition | type | revision_signature | occurred_at | lock_hash)`.
    ///
    /// Deterministic on the event's own identity (not on delivery attempt), so a
    /// duplicated/retried POST carries the same `event_id` and the receiver dedups.
    ///
    /// `lock_hash` disambiguates lock events, which carry no `revision_signature`:
    /// without it, two distinct locks on the same repo within the same second would
    /// synthesize the same id and the receiver would drop the second. It is empty
    /// for revision-producing events, so their id is unchanged.
    #[lore_macro::test_pub]
    fn event_id(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.partition.as_bytes());
        hasher.update(b"|");
        hasher.update(self.event_type.as_bytes());
        hasher.update(b"|");
        hasher.update(self.revision_signature.as_deref().unwrap_or("").as_bytes());
        hasher.update(b"|");
        hasher.update(self.occurred_at.as_bytes());
        hasher.update(b"|");
        hasher.update(self.lock_hash.as_deref().unwrap_or("").as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Renders the signed JSON payload. Nullable fields become JSON `null`.
    #[lore_macro::test_pub]
    fn to_payload(&self) -> Value {
        json!({
            "event_id": self.event_id(),
            "type": self.event_type,
            "partition": self.partition,
            "actor": self.actor,
            "branch": self.branch,
            "revision_signature": self.revision_signature,
            "revision_number": self.revision_number,
            "occurred_at": self.occurred_at,
            "client_ip": self.client_ip,
        })
    }
}

/// Computes the `X-Lorehub-Signature` header value
/// `sha256=<hex( HMAC_SHA256(secret, timestamp + "." + raw_body) )>` over the exact
/// bytes that will be `POSTed`. The timestamp is bound into the MAC to limit replay.
#[lore_macro::test_pub]
fn sign_event(secret: &str, timestamp: i64, raw_body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut signing_input = Vec::with_capacity(raw_body.len() + 16);
    signing_input.extend_from_slice(timestamp.to_string().as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(raw_body);
    let tag = hmac::sign(&key, &signing_input);
    format!("sha256={}", hex::encode(tag.as_ref()))
}

/// OpenTelemetry instruments for the notify hook (WP-066 Part 1 observability). A
/// failed POST is otherwise invisible (logged and dropped), so we cannot know the
/// loss rate. Cached in a `OnceLock` so the counter is built once, not per event —
/// mirrors `crate::util::cert_metrics`.
struct LorehubNotifyInstrumentProvider;

impl InstrumentProvider for LorehubNotifyInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.hooks"
    }
}

struct LorehubNotifyInstruments {
    deliveries: Counter<u64>,
    retries: Counter<u64>,
}

impl LorehubNotifyInstruments {
    fn new() -> Self {
        let provider = LorehubNotifyInstrumentProvider;
        let meter = provider.meter();
        Self {
            deliveries: meter
                .u64_counter(provider.scope_name("lorehub_notify.deliveries"))
                .with_description(
                    "lorehub_notify event POSTs to the Lorehub platform, by event_type + outcome",
                )
                .build(),
            retries: meter
                .u64_counter(provider.scope_name("lorehub_notify.retries"))
                .with_description(
                    "lorehub_notify POST retry attempts (WP-066 option C), by event_type",
                )
                .build(),
        }
    }

    fn instance() -> &'static LorehubNotifyInstruments {
        // Caches the counter against whatever meter the global provider yields on the
        // FIRST event. Safe because hooks fire long after telemetry init at boot; if
        // init ever moved after the first post-commit hook, this would pin a no-op
        // counter (same ordering assumption as `crate::util::cert_metrics`).
        static INSTANCE: OnceLock<LorehubNotifyInstruments> = OnceLock::new();
        INSTANCE.get_or_init(LorehubNotifyInstruments::new)
    }
}

/// Increment the delivery counter for one POST outcome. Fire-and-forget: metrics
/// must never affect delivery. `outcome` ∈
/// `success | http_error | transport_error | timeout | serialize_error`.
fn record_delivery(event_type: &'static str, outcome: &'static str) {
    LorehubNotifyInstruments::instance().deliveries.add(
        1,
        &[
            KeyValue::new("event_type", event_type),
            KeyValue::new("outcome", outcome),
        ],
    );
}

/// Increment the retry counter for one retried POST attempt (WP-066 option C).
/// Fire-and-forget; `event_type` is the only (bounded) label.
fn record_retry(event_type: &'static str) {
    LorehubNotifyInstruments::instance()
        .retries
        .add(1, &[KeyValue::new("event_type", event_type)]);
}

/// A configured `lorehub_notify` hook instance.
#[lore_macro::test_pub]
struct LorehubNotifyHook {
    webhook_url: String,
    hmac_secret: String,
    client: reqwest::Client,
    /// Bounded retry for a transient POST failure (WP-066 option C). `retry()` yields
    /// a fresh waiter per event, so the hook stays `Sync` and attempts don't share state.
    retry_policy: RetryPolicy,
}

#[async_trait]
impl Hook for LorehubNotifyHook {
    fn name(&self) -> &'static str {
        HOOK_NAME
    }

    fn hook_points(&self) -> &'static [HookPoint] {
        HOOK_POINTS
    }

    async fn post_handler(&self, ctx: &HookContext) -> Result<(), HookError> {
        let now = Utc::now();
        let timestamp = now.timestamp();
        let fields = EventFields::from_context(ctx, now);
        // `&'static str` label; safe as an OTel attribute value.
        let event_type = fields.event_type;

        // Serialize once; these exact bytes are both signed and sent.
        let raw_body = match serde_json::to_vec(&fields.to_payload()) {
            Ok(body) => body,
            Err(e) => {
                record_delivery(event_type, "serialize_error");
                return Err(HookError::execution_failed(
                    HOOK_NAME,
                    format!("serialize: {e}"),
                ));
            }
        };
        let signature = sign_event(&self.hmac_secret, timestamp, &raw_body);
        // Header values are stable across attempts (the signed body + timestamp don't
        // change), so the receiver dedups a retried POST on its deterministic `event_id`.
        let timestamp_header = timestamp.to_string();

        debug!(
            correlation_id = %ctx.correlation_id(),
            event_type = fields.event_type,
            partition = %fields.partition,
            "Posting lorehub event"
        );

        // Bounded retry (WP-066 option C): retry a transient failure — a transport
        // error/timeout, or a 5xx/429 — with backoff; a 4xx is permanent (bad
        // signature/shape) and fails fast. Only the TERMINAL outcome hits the delivery
        // counter; each retried attempt bumps the retries counter.
        let mut retry = self.retry_policy.retry();
        loop {
            let attempt = self
                .client
                .post(&self.webhook_url)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header("X-Lorehub-Timestamp", timestamp_header.as_str())
                .header("X-Lorehub-Signature", signature.as_str())
                .body(raw_body.clone())
                .send()
                .await;

            match attempt {
                Ok(response) if response.status().is_success() => {
                    record_delivery(event_type, "success");
                    return Ok(());
                }
                Ok(response) => {
                    let status = response.status();
                    let retryable = status.is_server_error()
                        || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
                    if retryable && retry.wait().await {
                        record_retry(event_type);
                        continue;
                    }
                    record_delivery(event_type, "http_error");
                    return Err(HookError::execution_failed(
                        HOOK_NAME,
                        format!("receiver returned {status}"),
                    ));
                }
                Err(e) => {
                    // Transport errors + timeouts are always transient — always retryable.
                    if retry.wait().await {
                        record_retry(event_type);
                        continue;
                    }
                    // A per-request timeout surfaces here too; split it for a cleaner signal.
                    let outcome = if e.is_timeout() {
                        "timeout"
                    } else {
                        "transport_error"
                    };
                    record_delivery(event_type, outcome);
                    return Err(HookError::execution_failed(HOOK_NAME, format!("post: {e}")));
                }
            }
        }
    }
}

/// Factory that builds [`LorehubNotifyHook`] from a `[hooks.lorehub_notify]` block.
#[lore_macro::test_pub]
struct LorehubNotifyHookFactory;

impl HookFactory for LorehubNotifyHookFactory {
    fn name(&self) -> &'static str {
        HOOK_NAME
    }

    fn create(&self, config: &toml::Value) -> Result<Box<dyn Hook>, HookError> {
        let webhook_url = config
            .get("webhook_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                HookError::config_error(HOOK_NAME, "missing required string 'webhook_url'")
            })?
            .to_string();

        let hmac_secret = config
            .get("hmac_secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                HookError::config_error(HOOK_NAME, "missing required string 'hmac_secret'")
            })?
            .to_string();

        if hmac_secret.is_empty() {
            return Err(HookError::config_error(
                HOOK_NAME,
                "'hmac_secret' must not be empty",
            ));
        }

        let timeout_secs = match config.get("timeout") {
            None => DEFAULT_TIMEOUT_SECS,
            Some(v) => {
                let secs = v.as_integer().ok_or_else(|| {
                    HookError::config_error(HOOK_NAME, "'timeout' must be an integer (seconds)")
                })?;
                let secs = u64::try_from(secs).map_err(|_err| {
                    HookError::config_error(HOOK_NAME, "'timeout' must be a positive integer")
                })?;
                if secs == 0 {
                    return Err(HookError::config_error(
                        HOOK_NAME,
                        "'timeout' must be a positive integer (seconds), not 0",
                    ));
                }
                secs
            }
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| HookError::init_error(HOOK_NAME, format!("build http client: {e}")))?;

        // Optional `[hooks.lorehub_notify.retry]` sub-table → RetrySettings; absent → the
        // default policy. Deserialized via serde (RetrySettings derives Deserialize), same
        // shape as the server's other retry knobs.
        let retry_policy = match config.get("retry") {
            None => RetryPolicy::builder()
                .with_initial_backoff_millis(DEFAULT_RETRY_INITIAL_BACKOFF_MS)
                .with_max_backoff_millis(DEFAULT_RETRY_MAX_BACKOFF_MS)
                .with_limit(DEFAULT_RETRY_LIMIT)
                .build(),
            Some(v) => {
                let settings: RetrySettings = v.clone().try_into().map_err(|e| {
                    HookError::config_error(HOOK_NAME, format!("invalid 'retry' table: {e}"))
                })?;
                RetryPolicy::from(&settings)
            }
        };

        Ok(Box::new(LorehubNotifyHook {
            webhook_url,
            hmac_secret,
            client,
            retry_policy,
        }))
    }
}

/// Registers the `lorehub_notify` hook factory. Called by the build.rs-generated
/// `register_all_hooks()`; the hook stays inert until `[hooks.lorehub_notify]`
/// sets `enabled = true`.
pub fn register(registry: &mut HookRegistry, _ctx: &HookRegistrationContext) {
    registry.register_hook(Box::new(LorehubNotifyHookFactory));
}
