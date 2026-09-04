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
const DEFAULT_RETRY_LIMIT: usize = 2;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS: u64 = 200;
const DEFAULT_RETRY_MAX_BACKOFF_MS: u64 = 2_000;

/// The lifecycle points this hook fires for — the full write set
/// (`BranchPush`/`BranchCreate`/`BranchDelete`/`RepositoryCreate`/`Obliterate`) plus
/// lock/unlock (`ResourceLock`/`ResourceUnlock`, CR-015).
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
/// bytes that will be POSTed. The timestamp is bound into the MAC to limit replay.
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
                let secs = u64::try_from(secs).map_err(|_| {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use chrono::TimeZone;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_revision::lore::RepositoryId;

    use super::*;

    /// A fixed time so payload + event_id are deterministic in tests.
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
            start_counting_stub_receiver(|_idx| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .await;
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
            start_counting_stub_receiver(|_idx| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .await;
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
            start_counting_stub_receiver(|_idx| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .await;
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
    /// itself is only observable through the OTel counter label (untestable
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
}
