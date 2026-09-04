// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Typed configuration for the remote notification plugin, and its startup
//! validation.
//!
//! The server reads `[notification] mode = "remote"` and then hands this plugin
//! the `[plugins.remote]` TOML table. Everything below is parsed and bounded
//! **before** any network I/O, so a misconfigured cell fails at boot rather than
//! at its first mutation.
//!
//! ```toml
//! [notification]
//! mode = "remote"
//!
//! [plugins.remote]
//! gateway_uri          = "https://gateway.notification.svc.cluster.local:8443"
//! cell_id              = "sfo3-cell-a"
//! placement_epoch      = 12
//! producer_instance_id = "loreserver-sfo3-cell-a-2"
//!
//! client_cert_path = "/var/run/secrets/commit0/cell-notification/tls.crt"
//! client_key_path  = "/var/run/secrets/commit0/cell-notification/tls.key"
//! trust_roots_path = "/var/run/secrets/commit0/cell-notification/ca.crt"
//!
//! queue_capacity     = 4096
//! request_timeout_ms = 2000
//! drain_timeout_ms   = 5000
//!
//! [plugins.remote.retry]
//! initial_backoff_ms = 50
//! max_backoff_ms     = 1000
//! max_attempts       = 3
//!
//! [plugins.remote.contract]
//! private_transport_version  = 1
//! durable_payload_version_min = 1
//! durable_payload_version_max = 1
//!
//! [plugins.remote.receiver]
//! membership_identity     = "loreserver-sfo3-cell-a-2"
//! lifecycle_generation    = 1
//! lag_readiness_threshold = 5000
//! checkpoint_interval_ms  = 1000
//! checkpoint_every_events = 256
//! idle_poll_ms            = 250
//! ```
//!
//! The whole `[plugins.remote.receiver]` table is optional, and its absence
//! means "this cell declares no required durable receiver". Present, it makes
//! the receiver's failure a readiness failure, so it is the switch that turns a
//! cell into one whose retention depends on this replica keeping up.
//!
//! Certificate material is referenced by path and never inlined, so no config
//! error message and no log line can carry a key.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::error::RemoteNotificationError;
use super::mode::PluginMode;
use super::wire::DURABLE_PAYLOAD_VERSION;
use super::wire::TRANSPORT_VERSION;

/// The registry name this plugin registers under, and the `[plugins.<name>]`
/// table it reads.
pub const PLUGIN_NAME: &str = "remote";

/// The only mode this plugin is selectable for. The other two are named and
/// validated in [`super::mode`], which owns the whole ladder.
const SELECTABLE_MODE: PluginMode = PluginMode::Remote;

/// Bounds on the ordinary live-hint queue. A queue of zero cannot accept an
/// event; an unbounded one is prohibited outright by the contract.
const QUEUE_CAPACITY_MIN: usize = 1;
const QUEUE_CAPACITY_MAX: usize = 1_048_576;
const QUEUE_CAPACITY_DEFAULT: usize = 4_096;

/// Bounds on a single live-hint Publish attempt.
const REQUEST_TIMEOUT_MIN_MS: u64 = 50;
const REQUEST_TIMEOUT_MAX_MS: u64 = 30_000;
const REQUEST_TIMEOUT_DEFAULT_MS: u64 = 2_000;

/// Bounds on the shutdown drain. Shutdown stops new enqueue, then drains
/// accepted ordinary events within this bound.
const DRAIN_TIMEOUT_MIN_MS: u64 = 0;
const DRAIN_TIMEOUT_MAX_MS: u64 = 60_000;
const DRAIN_TIMEOUT_DEFAULT_MS: u64 = 5_000;

/// Bounds on the bounded live-hint retry budget. `max_attempts` counts
/// RETRIES, matching `RetrySettings`' convention elsewhere in this crate.
const RETRY_LIMIT_MAX: usize = 10;
const RETRY_LIMIT_DEFAULT: usize = 3;
const RETRY_INITIAL_BACKOFF_DEFAULT_MS: u64 = 50;
const RETRY_MAX_BACKOFF_DEFAULT_MS: u64 = 1_000;
const RETRY_BACKOFF_MAX_MS: u64 = 60_000;

/// Contract bound on `cell_id`, from the notification-plane contract.
const CELL_ID_MAX_BYTES: usize = 63;

/// Contract bound on `producer_instance_id`, counted in UTF-8 **bytes**.
pub const PRODUCER_INSTANCE_ID_MAX_BYTES: usize = 128;

/// Bounds on the durable receiver's checkpoint cadence.
///
/// The cadence is a two-sided trade the contract does not pin a number for.
/// Too slow, and WP-119's retention reaper cannot advance, so a cell retains
/// rows it has already consumed. Too fast, and every applied event costs a
/// fenced transaction against the membership counter that every other writer
/// also serialises on. The defaults report at most once a second and at least
/// once every 256 applied events.
///
/// The floor is one millisecond rather than a sensible production minimum, for
/// the reason [`IDLE_POLL_MIN_MS`] gives: a bound that doubles as a
/// recommendation blocks the component tests that exercise the time-based
/// cadence, and the recommendation belongs in the default and the diagnostics
/// instead. Zero remains rejected, because a zero interval checkpoints on
/// every single event and turns the projection into the hot path.
const CHECKPOINT_INTERVAL_MIN_MS: u64 = 1;
const CHECKPOINT_INTERVAL_MAX_MS: u64 = 300_000;
const CHECKPOINT_INTERVAL_DEFAULT_MS: u64 = 1_000;
const CHECKPOINT_EVERY_EVENTS_MIN: u64 = 1;
const CHECKPOINT_EVERY_EVENTS_MAX: u64 = 100_000;
const CHECKPOINT_EVERY_EVENTS_DEFAULT: u64 = 256;

/// Bounds on the idle poll interval.
///
/// The floor exists to stop a busy loop, and only zero is one: at one
/// millisecond the receiver still yields between reads. It is deliberately not
/// set to a "sensible production minimum", because a floor that also has to be
/// a recommendation ends up blocking component tests that want a tight loop,
/// and a test that cannot run fast gets deleted rather than tuned. The
/// production guidance is the default, 250 ms; an operator who sets 1 ms is
/// asking for a thousand reads a second per replica and the diagnostics say so.
const IDLE_POLL_MIN_MS: u64 = 1;
const IDLE_POLL_MAX_MS: u64 = 60_000;
const IDLE_POLL_DEFAULT_MS: u64 = 250;

/// Contract bound on a durable receiver's membership identity. Not pinned by
/// the contract as a width; bounded here so a config cannot make an unbounded
/// diagnostic string.
const MEMBERSHIP_IDENTITY_MAX_BYTES: usize = 128;

/// The banner emitted when a cell runs with TLS disabled. Named so a test can
/// assert on the exact bytes.
pub const INSECURE_TRANSPORT_BANNER: &str = "WARNING: the remote notification plugin is configured with \
     `allow_insecure_transport_for_test = true`. The private gateway channel carries no TLS and \
     no client identity, so the cell's mTLS identity is NOT proven. This is a TEST configuration \
     and must not serve production traffic.";

/// Raw `[plugins.remote]` shape, before validation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Optional restatement of the selected mode. Present only so a
    /// `local-shadow-remote` deployment fails loudly here instead of silently
    /// running ordinary remote mode.
    mode: Option<String>,

    gateway_uri: String,
    cell_id: String,
    placement_epoch: u64,
    producer_instance_id: String,

    client_cert_path: Option<PathBuf>,
    client_key_path: Option<PathBuf>,
    trust_roots_path: Option<PathBuf>,

    #[serde(default)]
    allow_insecure_transport_for_test: bool,

    queue_capacity: Option<usize>,
    request_timeout_ms: Option<u64>,
    drain_timeout_ms: Option<u64>,

    #[serde(default)]
    retry: Option<RawRetry>,
    #[serde(default)]
    contract: Option<RawContract>,
    #[serde(default)]
    receiver: Option<RawReceiver>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRetry {
    initial_backoff_ms: Option<u64>,
    max_backoff_ms: Option<u64>,
    max_attempts: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContract {
    private_transport_version: Option<u32>,
    durable_payload_version_min: Option<u32>,
    durable_payload_version_max: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReceiver {
    membership_identity: String,
    lifecycle_generation: u64,
    lag_readiness_threshold: u64,

    checkpoint_interval_ms: Option<u64>,
    checkpoint_every_events: Option<u64>,
    idle_poll_ms: Option<u64>,
}

/// The bounded live-hint retry budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryConfig {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    /// Number of RETRIES, so `limit + 1` total attempts.
    pub limit: usize,
}

/// The pinned contract versions this cell will speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractConfig {
    pub private_transport_version: u32,
    pub durable_payload_version_min: u32,
    pub durable_payload_version_max: u32,
}

/// Durable-receiver identity and cadence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverConfig {
    pub membership_identity: String,
    /// The generation floor this replica expects.
    ///
    /// The authoritative generation is **allocated** by WP-119's membership
    /// counter at join, not chosen here. This value is a diagnostic floor: a
    /// replica that joins below it has come back against a cell whose counter
    /// moved backwards, which is worth a loud log even though the allocated
    /// number is the one that fences.
    pub lifecycle_generation: u64,
    pub lag_readiness_threshold: u64,
    /// Longest interval between two checkpoint reports while events flow.
    pub checkpoint_interval: Duration,
    /// Most events applied between two checkpoint reports.
    pub checkpoint_every_events: u64,
    /// How long the receiver waits after a caught-up read before asking again.
    pub idle_poll: Duration,
}

/// mTLS material, referenced by path. The bytes are read at construction and
/// never held in a `Debug` or `Display` surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtlsConfig {
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub trust_roots_path: PathBuf,
}

/// The validated configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteNotificationConfig {
    pub gateway_uri: String,
    pub cell_id: String,
    pub placement_epoch: u64,
    pub producer_instance_id: String,
    /// `None` only in the explicitly-marked insecure test configuration.
    pub mtls: Option<MtlsConfig>,
    pub queue_capacity: usize,
    pub request_timeout: Duration,
    pub drain_timeout: Duration,
    pub retry: RetryConfig,
    pub contract: ContractConfig,
    /// `None` until a cell declares a required durable receiver. Phase 3 makes
    /// a required receiver's failure a readiness failure.
    pub receiver: Option<ReceiverConfig>,
}

/// The contract's `cell_id` grammar: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`.
pub fn cell_id_is_valid(cell_id: &str) -> bool {
    if cell_id.is_empty() || cell_id.len() > CELL_ID_MAX_BYTES {
        return false;
    }
    let bytes = cell_id.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'-')
}

impl RemoteNotificationConfig {
    /// Parses and validates the `[plugins.remote]` table.
    ///
    /// # Errors
    /// Returns a [`RemoteNotificationError`] naming the offending field. No
    /// error message carries a path's contents or any credential.
    pub fn parse(config: &toml::Value) -> Result<Self, RemoteNotificationError> {
        let raw: RawConfig = config
            .clone()
            .try_into()
            .map_err(|e| RemoteNotificationError::ConfigParse(e.to_string()))?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Result<Self, RemoteNotificationError> {
        // The mode ladder itself lives in `super::mode`. Here it is only
        // validated: an operator who restates the mode in this table must
        // restate the one this plugin is actually being selected for, so a
        // `local-shadow-remote` deployment fails loudly rather than silently
        // running ordinary remote mode with its public service unmounted.
        if let Some(mode) = raw.mode.as_deref() {
            PluginMode::parse(mode)?.require_selectable()?;
        }

        let gateway_uri = raw.gateway_uri.trim().to_string();
        if gateway_uri.is_empty() {
            return Err(RemoteNotificationError::field("gateway_uri", "must be set"));
        }
        let is_https = gateway_uri.starts_with("https://");
        if !is_https && !raw.allow_insecure_transport_for_test {
            return Err(RemoteNotificationError::field(
                "gateway_uri",
                "must use https://; the private gateway channel is authenticated by the cell's \
                 mTLS identity and an insecure endpoint cannot carry it",
            ));
        }

        // The contract makes `placement_epoch` a required monotonic integer
        // naming the current publication authority. Zero is the protobuf
        // default, so it means "absent" rather than "epoch zero"; a cell
        // configured with it would have every publish rejected as a stale
        // placement and burn its whole retry budget on each hint.
        if raw.placement_epoch == 0 {
            return Err(RemoteNotificationError::field(
                "placement_epoch",
                "must be the cell's current non-zero placement epoch; zero is the absent value",
            ));
        }

        if !cell_id_is_valid(&raw.cell_id) {
            return Err(RemoteNotificationError::field(
                "cell_id",
                "must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ and be at most 63 bytes",
            ));
        }

        if raw.producer_instance_id.is_empty() {
            return Err(RemoteNotificationError::field(
                "producer_instance_id",
                "must be set; it is the cell's bounded diagnostic producer identity",
            ));
        }
        if raw.producer_instance_id.len() > PRODUCER_INSTANCE_ID_MAX_BYTES {
            return Err(RemoteNotificationError::field(
                "producer_instance_id",
                format!("must be at most {PRODUCER_INSTANCE_ID_MAX_BYTES} UTF-8 bytes"),
            ));
        }

        let mtls = Self::validate_mtls(&raw)?;

        let queue_capacity = raw.queue_capacity.unwrap_or(QUEUE_CAPACITY_DEFAULT);
        if !(QUEUE_CAPACITY_MIN..=QUEUE_CAPACITY_MAX).contains(&queue_capacity) {
            return Err(RemoteNotificationError::field(
                "queue_capacity",
                format!("must be between {QUEUE_CAPACITY_MIN} and {QUEUE_CAPACITY_MAX}"),
            ));
        }

        let request_timeout_ms = raw.request_timeout_ms.unwrap_or(REQUEST_TIMEOUT_DEFAULT_MS);
        if !(REQUEST_TIMEOUT_MIN_MS..=REQUEST_TIMEOUT_MAX_MS).contains(&request_timeout_ms) {
            return Err(RemoteNotificationError::field(
                "request_timeout_ms",
                format!("must be between {REQUEST_TIMEOUT_MIN_MS} and {REQUEST_TIMEOUT_MAX_MS}"),
            ));
        }

        let drain_timeout_ms = raw.drain_timeout_ms.unwrap_or(DRAIN_TIMEOUT_DEFAULT_MS);
        if !(DRAIN_TIMEOUT_MIN_MS..=DRAIN_TIMEOUT_MAX_MS).contains(&drain_timeout_ms) {
            return Err(RemoteNotificationError::field(
                "drain_timeout_ms",
                format!("must be between {DRAIN_TIMEOUT_MIN_MS} and {DRAIN_TIMEOUT_MAX_MS}"),
            ));
        }

        let retry = Self::validate_retry(raw.retry.as_ref())?;
        let contract = Self::validate_contract(raw.contract.as_ref())?;
        let receiver = Self::validate_receiver(raw.receiver.as_ref())?;

        Ok(Self {
            gateway_uri,
            cell_id: raw.cell_id,
            placement_epoch: raw.placement_epoch,
            producer_instance_id: raw.producer_instance_id,
            mtls,
            queue_capacity,
            request_timeout: Duration::from_millis(request_timeout_ms),
            drain_timeout: Duration::from_millis(drain_timeout_ms),
            retry,
            contract,
            receiver,
        })
    }

    fn validate_mtls(raw: &RawConfig) -> Result<Option<MtlsConfig>, RemoteNotificationError> {
        let present = (
            raw.client_cert_path.clone(),
            raw.client_key_path.clone(),
            raw.trust_roots_path.clone(),
        );
        match present {
            (Some(client_cert_path), Some(client_key_path), Some(trust_roots_path)) => {
                Ok(Some(MtlsConfig {
                    client_cert_path,
                    client_key_path,
                    trust_roots_path,
                }))
            }
            (None, None, None) => {
                if raw.allow_insecure_transport_for_test {
                    Ok(None)
                } else {
                    Err(RemoteNotificationError::field(
                        "client_cert_path",
                        "mTLS material is required: set client_cert_path, client_key_path, and \
                         trust_roots_path",
                    ))
                }
            }
            // A partial set is always a fault, insecure test mode included: it
            // means an operator meant to configure mTLS and missed a field.
            (cert, key, _) => {
                let missing = if cert.is_none() {
                    "client_cert_path"
                } else if key.is_none() {
                    "client_key_path"
                } else {
                    "trust_roots_path"
                };
                Err(RemoteNotificationError::field(
                    missing,
                    "mTLS material is partially configured; set all three of client_cert_path, \
                     client_key_path, and trust_roots_path, or none of them",
                ))
            }
        }
    }

    fn validate_retry(raw: Option<&RawRetry>) -> Result<RetryConfig, RemoteNotificationError> {
        let limit = raw
            .and_then(|r| r.max_attempts)
            .unwrap_or(RETRY_LIMIT_DEFAULT);
        if limit > RETRY_LIMIT_MAX {
            return Err(RemoteNotificationError::field(
                "retry.max_attempts",
                format!("must be at most {RETRY_LIMIT_MAX} retries"),
            ));
        }
        let initial_ms = raw
            .and_then(|r| r.initial_backoff_ms)
            .unwrap_or(RETRY_INITIAL_BACKOFF_DEFAULT_MS);
        let max_ms = raw
            .and_then(|r| r.max_backoff_ms)
            .unwrap_or(RETRY_MAX_BACKOFF_DEFAULT_MS);
        if initial_ms == 0 || initial_ms > RETRY_BACKOFF_MAX_MS {
            return Err(RemoteNotificationError::field(
                "retry.initial_backoff_ms",
                format!("must be between 1 and {RETRY_BACKOFF_MAX_MS}"),
            ));
        }
        if max_ms < initial_ms || max_ms > RETRY_BACKOFF_MAX_MS {
            return Err(RemoteNotificationError::field(
                "retry.max_backoff_ms",
                format!(
                    "must be at least retry.initial_backoff_ms and at most {RETRY_BACKOFF_MAX_MS}"
                ),
            ));
        }
        Ok(RetryConfig {
            initial_backoff: Duration::from_millis(initial_ms),
            max_backoff: Duration::from_millis(max_ms),
            limit,
        })
    }

    fn validate_contract(
        raw: Option<&RawContract>,
    ) -> Result<ContractConfig, RemoteNotificationError> {
        let private_transport_version = raw
            .and_then(|c| c.private_transport_version)
            .unwrap_or(TRANSPORT_VERSION);
        if private_transport_version != TRANSPORT_VERSION {
            return Err(RemoteNotificationError::IncompatibleTransportVersion {
                configured: private_transport_version,
                supported: TRANSPORT_VERSION,
            });
        }
        let min = raw
            .and_then(|c| c.durable_payload_version_min)
            .unwrap_or(DURABLE_PAYLOAD_VERSION);
        let max = raw
            .and_then(|c| c.durable_payload_version_max)
            .unwrap_or(DURABLE_PAYLOAD_VERSION);
        if min > max {
            return Err(RemoteNotificationError::field(
                "contract.durable_payload_version_min",
                "must not exceed contract.durable_payload_version_max",
            ));
        }
        if !(min..=max).contains(&DURABLE_PAYLOAD_VERSION) {
            return Err(RemoteNotificationError::IncompatibleDurablePayloadVersion {
                min,
                max,
                supported: DURABLE_PAYLOAD_VERSION,
            });
        }
        Ok(ContractConfig {
            private_transport_version,
            durable_payload_version_min: min,
            durable_payload_version_max: max,
        })
    }

    fn validate_receiver(
        raw: Option<&RawReceiver>,
    ) -> Result<Option<ReceiverConfig>, RemoteNotificationError> {
        let Some(raw) = raw else { return Ok(None) };
        if raw.membership_identity.is_empty()
            || raw.membership_identity.len() > MEMBERSHIP_IDENTITY_MAX_BYTES
        {
            return Err(RemoteNotificationError::field(
                "receiver.membership_identity",
                format!("must be 1..={MEMBERSHIP_IDENTITY_MAX_BYTES} UTF-8 bytes"),
            ));
        }
        if raw.lifecycle_generation == 0 {
            return Err(RemoteNotificationError::field(
                "receiver.lifecycle_generation",
                "must be a non-zero monotonic generation; zero cannot fence a predecessor",
            ));
        }
        if raw.lag_readiness_threshold == 0 {
            return Err(RemoteNotificationError::field(
                "receiver.lag_readiness_threshold",
                "must be non-zero; a zero threshold can never be satisfied",
            ));
        }
        let checkpoint_interval = Self::bounded_millis(
            "receiver.checkpoint_interval_ms",
            raw.checkpoint_interval_ms,
            CHECKPOINT_INTERVAL_MIN_MS,
            CHECKPOINT_INTERVAL_MAX_MS,
            CHECKPOINT_INTERVAL_DEFAULT_MS,
        )?;
        let idle_poll = Self::bounded_millis(
            "receiver.idle_poll_ms",
            raw.idle_poll_ms,
            IDLE_POLL_MIN_MS,
            IDLE_POLL_MAX_MS,
            IDLE_POLL_DEFAULT_MS,
        )?;
        let checkpoint_every_events = raw
            .checkpoint_every_events
            .unwrap_or(CHECKPOINT_EVERY_EVENTS_DEFAULT);
        if !(CHECKPOINT_EVERY_EVENTS_MIN..=CHECKPOINT_EVERY_EVENTS_MAX)
            .contains(&checkpoint_every_events)
        {
            return Err(RemoteNotificationError::field(
                "receiver.checkpoint_every_events",
                format!(
                    "must be {CHECKPOINT_EVERY_EVENTS_MIN}..={CHECKPOINT_EVERY_EVENTS_MAX}; a \
                     receiver that never checkpoints blocks retention forever"
                ),
            ));
        }

        Ok(Some(ReceiverConfig {
            membership_identity: raw.membership_identity.clone(),
            lifecycle_generation: raw.lifecycle_generation,
            lag_readiness_threshold: raw.lag_readiness_threshold,
            checkpoint_interval,
            checkpoint_every_events,
            idle_poll,
        }))
    }

    /// Bound one optional millisecond setting, or take its default.
    ///
    /// # Errors
    /// [`RemoteNotificationError::ConfigField`] naming the field.
    fn bounded_millis(
        field: &'static str,
        value: Option<u64>,
        min: u64,
        max: u64,
        default: u64,
    ) -> Result<Duration, RemoteNotificationError> {
        let millis = value.unwrap_or(default);
        if !(min..=max).contains(&millis) {
            return Err(RemoteNotificationError::field(
                field,
                format!("must be {min}..={max} milliseconds"),
            ));
        }
        Ok(Duration::from_millis(millis))
    }

    /// Diagnostics safe to report at boot and on the diagnostics surface. Never
    /// includes a path to credential material, and never the material itself.
    pub fn diagnostics(&self) -> Vec<(&'static str, String)> {
        vec![
            ("mode", SELECTABLE_MODE.as_str().to_string()),
            ("cell_id", self.cell_id.clone()),
            ("placement_epoch", self.placement_epoch.to_string()),
            ("queue_capacity", self.queue_capacity.to_string()),
            (
                "request_timeout_ms",
                self.request_timeout.as_millis().to_string(),
            ),
            (
                "drain_timeout_ms",
                self.drain_timeout.as_millis().to_string(),
            ),
            ("retry_limit", self.retry.limit.to_string()),
            (
                "private_transport_version",
                self.contract.private_transport_version.to_string(),
            ),
            (
                "durable_payload_version_range",
                format!(
                    "{}..={}",
                    self.contract.durable_payload_version_min,
                    self.contract.durable_payload_version_max
                ),
            ),
            ("mtls_configured", self.mtls.is_some().to_string()),
            ("required_receiver", self.receiver.is_some().to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(toml_text: &str) -> toml::Value {
        toml::from_str(toml_text).expect("test config parses as TOML")
    }

    const MINIMAL: &str = r#"
        gateway_uri = "https://gateway.internal:8443"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "loreserver-sfo3-cell-a-2"
        client_cert_path = "/secrets/tls.crt"
        client_key_path = "/secrets/tls.key"
        trust_roots_path = "/secrets/ca.crt"
    "#;

    #[test]
    fn a_minimal_config_parses_with_bounded_defaults() {
        let cfg = RemoteNotificationConfig::parse(&table(MINIMAL)).expect("valid");
        assert_eq!(cfg.queue_capacity, QUEUE_CAPACITY_DEFAULT);
        assert_eq!(cfg.retry.limit, RETRY_LIMIT_DEFAULT);
        assert_eq!(cfg.contract.private_transport_version, TRANSPORT_VERSION);
        assert!(cfg.receiver.is_none());
        assert!(cfg.mtls.is_some());
    }

    #[test]
    fn an_insecure_endpoint_is_rejected_without_the_explicit_test_escape() {
        let cfg = table(
            r#"
            gateway_uri = "http://gateway.internal:8080"
            cell_id = "sfo3-cell-a"
            placement_epoch = 12
            producer_instance_id = "p"
            client_cert_path = "/secrets/tls.crt"
            client_key_path = "/secrets/tls.key"
            trust_roots_path = "/secrets/ca.crt"
        "#,
        );
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("insecure endpoint");
        assert!(matches!(
            err,
            RemoteNotificationError::ConfigField {
                field: "gateway_uri",
                ..
            }
        ));
    }

    #[test]
    fn missing_mtls_material_is_rejected() {
        let cfg = table(
            r#"
            gateway_uri = "https://gateway.internal:8443"
            cell_id = "sfo3-cell-a"
            placement_epoch = 12
            producer_instance_id = "p"
        "#,
        );
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("no mTLS");
        assert!(matches!(
            err,
            RemoteNotificationError::ConfigField {
                field: "client_cert_path",
                ..
            }
        ));
    }

    #[test]
    fn partial_mtls_material_is_rejected_even_in_the_insecure_test_mode() {
        let cfg = table(
            r#"
            gateway_uri = "http://127.0.0.1:1"
            cell_id = "sfo3-cell-a"
            placement_epoch = 12
            producer_instance_id = "p"
            allow_insecure_transport_for_test = true
            client_cert_path = "/secrets/tls.crt"
        "#,
        );
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("partial mTLS");
        assert!(matches!(
            err,
            RemoteNotificationError::ConfigField {
                field: "client_key_path",
                ..
            }
        ));
    }

    #[test]
    fn local_shadow_remote_is_rejected_rather_than_silently_downgraded() {
        let cfg = table(&format!("mode = \"local-shadow-remote\"\n{MINIMAL}"));
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("shadow composition");
        let RemoteNotificationError::ConfigField { field, reason } = err else {
            panic!("expected a field error");
        };
        assert_eq!(field, "mode");
        assert!(reason.contains("server-level composition"));
    }

    #[test]
    fn an_unknown_mode_is_rejected() {
        let cfg = table(&format!("mode = \"nats\"\n{MINIMAL}"));
        assert!(RemoteNotificationConfig::parse(&cfg).is_err());
    }

    #[test]
    fn an_incompatible_transport_version_is_rejected_at_startup() {
        let cfg = table(&format!(
            "{MINIMAL}\n[contract]\nprivate_transport_version = 2\n"
        ));
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("transport version");
        assert!(matches!(
            err,
            RemoteNotificationError::IncompatibleTransportVersion {
                configured: 2,
                supported: 1
            }
        ));
    }

    #[test]
    fn a_durable_payload_range_excluding_this_build_is_rejected_at_startup() {
        let cfg = table(&format!(
            "{MINIMAL}\n[contract]\ndurable_payload_version_min = 2\ndurable_payload_version_max = 3\n"
        ));
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("payload range");
        assert!(matches!(
            err,
            RemoteNotificationError::IncompatibleDurablePayloadVersion {
                min: 2,
                max: 3,
                supported: 1
            }
        ));
    }

    #[test]
    fn an_unbounded_queue_cannot_be_configured() {
        let cfg = table(&format!("{MINIMAL}\nqueue_capacity = 0\n"));
        assert!(RemoteNotificationConfig::parse(&cfg).is_err());
        let cfg = table(&format!("{MINIMAL}\nqueue_capacity = 99999999\n"));
        assert!(RemoteNotificationConfig::parse(&cfg).is_err());
    }

    #[test]
    fn an_unknown_config_key_is_rejected_rather_than_ignored() {
        let cfg = table(&format!("{MINIMAL}\nnats_url = \"nats://broker:4222\"\n"));
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("unknown key");
        assert!(matches!(err, RemoteNotificationError::ConfigParse(_)));
    }

    #[test]
    fn cell_id_grammar_matches_the_contract() {
        assert!(cell_id_is_valid("sfo3-cell-a"));
        assert!(cell_id_is_valid("a"));
        assert!(cell_id_is_valid("a1"));
        assert!(!cell_id_is_valid(""));
        assert!(!cell_id_is_valid("sfo3_cell_a"));
        assert!(!cell_id_is_valid("-sfo3"));
        assert!(!cell_id_is_valid("sfo3-"));
        assert!(!cell_id_is_valid("SFO3"));
        assert!(!cell_id_is_valid(&"a".repeat(CELL_ID_MAX_BYTES + 1)));
        assert!(cell_id_is_valid(&"a".repeat(CELL_ID_MAX_BYTES)));
    }

    #[test]
    fn a_zero_placement_epoch_is_rejected() {
        let cfg = table(&MINIMAL.replace("placement_epoch = 12", "placement_epoch = 0"));
        let err = RemoteNotificationConfig::parse(&cfg).expect_err("zero placement epoch");
        assert!(matches!(
            err,
            RemoteNotificationError::ConfigField {
                field: "placement_epoch",
                ..
            }
        ));
    }

    #[test]
    fn a_zero_receiver_generation_is_rejected() {
        let cfg = table(&format!(
            "{MINIMAL}\n[receiver]\nmembership_identity = \"r\"\nlifecycle_generation = 0\nlag_readiness_threshold = 10\n"
        ));
        assert!(RemoteNotificationConfig::parse(&cfg).is_err());
    }

    #[test]
    fn diagnostics_never_expose_credential_paths_or_material() {
        let cfg = RemoteNotificationConfig::parse(&table(MINIMAL)).expect("valid");
        let rendered = format!("{:?}", cfg.diagnostics());
        assert!(!rendered.contains("/secrets/"));
        assert!(!rendered.contains("tls.key"));
        assert!(rendered.contains("mtls_configured"));
    }
}
