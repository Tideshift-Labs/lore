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
//! here. Delivery is therefore **at-least-once and possibly lossy** (no retry/outbox in
//! v1) — the receiver is idempotent on `event_id`, which this hook synthesizes
//! deterministically.
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
//! timeout     = 10           # HTTP request timeout, seconds (optional, default 10)
//! ```

use std::time::Duration;

use async_trait::async_trait;
use chrono::SecondsFormat;
use chrono::Utc;
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

/// Default HTTP request timeout (seconds) when `timeout` is omitted from config.
/// Kept comfortably under the dispatcher's 30 s post-handler timeout.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// The lifecycle points this hook fires for — the full write set
/// (`BranchPush`/`BranchCreate`/`BranchDelete`/`RepositoryCreate`/`Obliterate`).
const HOOK_POINTS: &[HookPoint] = &[
    HookPoint::BranchPush,
    HookPoint::BranchCreate,
    HookPoint::BranchDelete,
    HookPoint::RepositoryCreate,
    HookPoint::Obliterate,
];

/// Maps a [`HookPoint`] to the Lorehub event-type string in the contract.
fn event_type(point: HookPoint) -> &'static str {
    match point {
        HookPoint::BranchPush => "branch_push",
        HookPoint::BranchCreate => "branch_create",
        HookPoint::BranchDelete => "branch_delete",
        HookPoint::RepositoryCreate => "repository_create",
        HookPoint::Obliterate => "obliterate",
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
        }
    }

    /// Synthesizes the deterministic idempotency key
    /// `blake3(partition | type | revision_signature | occurred_at)`.
    ///
    /// Deterministic on the event's own identity (not on delivery attempt), so a
    /// duplicated/retried POST carries the same `event_id` and the receiver dedups.
    fn event_id(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.partition.as_bytes());
        hasher.update(b"|");
        hasher.update(self.event_type.as_bytes());
        hasher.update(b"|");
        hasher.update(self.revision_signature.as_deref().unwrap_or("").as_bytes());
        hasher.update(b"|");
        hasher.update(self.occurred_at.as_bytes());
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

/// A configured `lorehub_notify` hook instance.
struct LorehubNotifyHook {
    webhook_url: String,
    hmac_secret: String,
    client: reqwest::Client,
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

        // Serialize once; these exact bytes are both signed and sent.
        let raw_body = serde_json::to_vec(&fields.to_payload())
            .map_err(|e| HookError::execution_failed(HOOK_NAME, format!("serialize: {e}")))?;
        let signature = sign_event(&self.hmac_secret, timestamp, &raw_body);

        debug!(
            correlation_id = %ctx.correlation_id(),
            event_type = fields.event_type,
            partition = %fields.partition,
            "Posting lorehub event"
        );

        let response = self
            .client
            .post(&self.webhook_url)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("X-Lorehub-Timestamp", timestamp.to_string())
            .header("X-Lorehub-Signature", signature)
            .body(raw_body)
            .send()
            .await
            .map_err(|e| HookError::execution_failed(HOOK_NAME, format!("post: {e}")))?;

        if !response.status().is_success() {
            return Err(HookError::execution_failed(
                HOOK_NAME,
                format!("receiver returned {}", response.status()),
            ));
        }

        Ok(())
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
                u64::try_from(secs).map_err(|_| {
                    HookError::config_error(HOOK_NAME, "'timeout' must be a positive integer")
                })?
            }
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| HookError::init_error(HOOK_NAME, format!("build http client: {e}")))?;

        Ok(Box::new(LorehubNotifyHook {
            webhook_url,
            hmac_secret,
            client,
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
}
