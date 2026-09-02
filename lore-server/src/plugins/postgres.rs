// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Postgres store plugin factories (CR-007).
//!
//! Adapts the `lore-postgres` co-located, off-AWS backend to loreserver's plugin
//! registry, mirroring `plugins/aws.rs`:
//! - [`PostgresImmutableStorePluginFactory`] — fragment representations and
//!   bytes in S3-compatible object storage, with lifecycle, associations, and
//!   an exact rebuildable metering projection in Postgres.
//! - [`PostgresMutableStorePluginFactory`] — branch-tip CAS in Postgres.
//! - [`PostgresLockStorePluginFactory`] — advisory locks in Postgres.
//!
//! All three select via `mode = "postgres"` on the same plugin-factory registry
//! the AWS plugins use (INV-R). `build.rs` auto-discovers the [`register`] fn and
//! wires it into the generated `plugins/mod.rs` — do not edit that file.
//!
//! NOTE: store implementations land incrementally (CR-007). Until a given store
//! is implemented, its `create()` returns [`PluginInitError`]; `validate_config`
//! already parses the config so misconfiguration surfaces early.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use lore_base::error::PluginConfigError;
use lore_base::error::PluginInitError;
use lore_base::runtime::runtime;
use lore_postgres::domain::DatabaseIdentity;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::BudgetPin;
use lore_postgres::domain::fragments::CellProviderBoundary;
use lore_postgres::domain::fragments::FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS;
use lore_postgres::domain::fragments::FRAGMENT_SCHEMA_VERSION;
use lore_postgres::domain::fragments::FragmentDatabaseIdentity;
use lore_postgres::domain::fragments::FragmentDispatchRuntimeConfig;
use lore_postgres::domain::fragments::FragmentDispatchTls;
use lore_postgres::domain::fragments::FragmentProcessPoolInventory;
use lore_postgres::domain::fragments::FragmentWriteCapabilityCutover;
use lore_postgres::domain::fragments::InFlightPutBound;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::ProviderCapabilities;
use lore_postgres::domain::fragments::ValidatedFragmentProcessPoolInventory;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::immutable_store::FragmentProviderRuntimeSettings;
use lore_postgres::store::immutable_store::ObjectStoreSettings;
use lore_postgres::store::immutable_store::PostgresImmutableStore;
use lore_postgres::store::lock_store::PostgresLockStore;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_revision::lock::LockStore;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use serde::Deserialize;

use crate::plugins::ImmutableStorePluginFactory;
use crate::plugins::LockStorePluginFactory;
use crate::plugins::MutableStorePluginFactory;
use crate::plugins::PluginError;
use crate::plugins::PluginRegistry;

const PLUGIN_NAME: &str = "postgres";

/// Connection config shared by the Postgres-backed stores.
///
/// Each store group is configured under its own `[plugins.postgres.*]` table but
/// shares this connection shape. The immutable store extends it with an
/// object-storage sub-config for fragment bytes (added with that impl).
#[derive(Debug, Clone, Deserialize)]
pub struct PostgresStoreConfig {
    /// Postgres connection string, e.g. `postgres://user:pass@host:5432/lore`.
    pub url: String,
    /// Max pooled connections (default 10).
    #[serde(default = "default_pool_max")]
    pub pool_max: u32,
    /// Optional path to a PEM CA bundle for the Postgres TLS trust store (e.g.
    /// DO Managed Postgres's per-cluster `ca-certificate.crt`). When unset, the
    /// platform trust store is used. TLS itself is driven by the URL's `sslmode`
    /// (default `prefer`); set `sslmode=require` in the URL to enforce it.
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    /// Skip Postgres server-certificate verification (encrypt-only, libpq
    /// `require` semantics). MITM-exposed; off by default. Use only when you
    /// cannot supply the cluster CA via `ca_cert_path`. rustls always verifies
    /// otherwise, so `sslmode=require` behaves like `verify-ca`.
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
    /// Max pooled connections for the CR-029 domain coordinator specifically.
    ///
    /// Deliberately its own knob with a small default rather than inheriting
    /// `pool_max`. The coordinator is the fourth pool alongside immutable,
    /// mutable, and lock; an enabled fragment provider adds the separately
    /// credentialed dispatch pool as the fifth. Composition accounts for all
    /// five configured maxima against the hard process budget. Inheriting a
    /// `pool_max` of 10 here would consume half that entire budget for a
    /// subsystem that is idle until cutover. The two things it actually does
    /// before then - bootstrap DDL and a singleton state read - need one
    /// connection, and the backfill walks one repository at a time. Raise it
    /// only while keeping the five-pool checked sum within budget.
    #[serde(default = "default_domain_pool_max")]
    pub domain_pool_max: u32,
    /// S3-compatible object storage for fragment bytes and authoritative
    /// representation metadata. Required by the immutable-store factory;
    /// unused (and typically absent) for the mutable/lock stores, which keep
    /// everything in Postgres.
    #[serde(default)]
    pub object_store: Option<ObjectStoreConfig>,
    /// Optional governed provider route for WP-118 fragment lifecycle I/O.
    /// Absence and `enabled = false` leave the exact legacy route active.
    #[serde(default)]
    pub fragment_provider: Option<FragmentProviderConfig>,
    /// CR-031's bounded concurrent in-flight put count for the WP-118 fragment
    /// lifecycle provider seam.
    ///
    /// CR-031 removed the pre-admission body spool (R-BLOCK-3) and bounds
    /// memory and provider pressure with the existing 256 KiB ingress cap plus
    /// this count instead, which is why the number is configuration rather than
    /// a constant.
    ///
    /// The value is consumed only when the nested `fragment_provider` block is
    /// enabled. Absent or disabled provider configuration leaves this bound
    /// inert and constructs no dispatch pool or gateway.
    ///
    /// An impossible value fails
    /// the store's `create()`, so a cell configured with one does not boot. The
    /// check lives in [`parse_config`], which every `create()` and the
    /// `validate_config` trait method both call. **It is deliberately not in
    /// `validate_config` alone**, because that method is not on loreserver's
    /// boot path — `server.rs` reaches `create()` directly — so a check written
    /// only there would refuse nothing at startup while reading as though it
    /// did.
    ///
    /// The field sits on the shared connection shape, so all three factories
    /// refuse it. Only the immutable store will consume it, but an operator who
    /// puts it under the mutable or lock section should still be told the value
    /// is impossible rather than that it was ignored.
    #[serde(default = "default_fragment_in_flight_puts")]
    pub fragment_in_flight_puts: u32,
    /// How long a fragment put waits for one of those slots before failing
    /// closed. Milliseconds; must be positive.
    #[serde(default = "default_fragment_put_admission_wait_millis")]
    pub fragment_put_admission_wait_millis: u64,
}

/// S3-compatible object-storage sub-config for immutable fragment objects.
/// Keys mirror the endpoint/region/bucket/path-style that `lore-aws` exposes so
/// the same backend can point at DO Spaces, MinIO, or LocalStack.
#[derive(Debug, Clone, Deserialize)]
pub struct ObjectStoreConfig {
    /// Bucket holding fragment payloads.
    pub bucket: String,
    /// Optional endpoint URL (set for S3-compatible stores like Spaces/MinIO).
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// Optional region.
    #[serde(default)]
    pub region: Option<String>,
    /// Force path-style addressing (required for S3-compatible stores behind
    /// non-AWS hostnames like MinIO in Docker).
    #[serde(default)]
    pub force_path_style: bool,
    /// Slow-operation log threshold in milliseconds.
    #[serde(default = "default_slow_threshold")]
    pub slow_operation_threshold_millis: u64,
    /// Per-operation timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_millis: u64,
    /// Whether to HEAD the bucket at startup to fail fast on misconfiguration.
    #[serde(default = "default_validate_bucket_on_startup")]
    pub validate_bucket_on_startup: bool,
}

/// Raw optional WP-118 provider configuration.
///
/// Fields stay optional at deserialization so an explicitly disabled block
/// needs only `enabled = false`. [`enabled_fragment_provider_config`] converts
/// an enabled block into a fully required typed value before any construction.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    pub dispatch_postgres_url: Option<String>,
    pub dispatch_ca_cert_path: Option<String>,
    pub dispatch_pool_max: Option<u32>,
    pub dispatch_connect_timeout_millis: Option<u64>,
    pub dispatch_acquire_timeout_millis: Option<u64>,
    pub dispatch_statement_timeout_millis: Option<u64>,
    pub dispatch_lock_timeout_millis: Option<u64>,
    pub provider_late_effect_bound_millis: Option<u64>,
    pub provider_boundary_id: Option<String>,
    pub endpoint_host: Option<String>,
    pub region: Option<String>,
    pub budget_revision: Option<String>,
    pub budget_fence: Option<u64>,
    pub provider_write_authority_revision: Option<String>,
}

impl fmt::Debug for FragmentProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FragmentProviderConfig")
            .field("enabled", &self.enabled)
            .field(
                "dispatch_postgres_url",
                &self.dispatch_postgres_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "dispatch_ca_cert_path",
                &self.dispatch_ca_cert_path.as_ref().map(|_| "[REDACTED]"),
            )
            .field("dispatch_pool_max", &self.dispatch_pool_max)
            .field(
                "dispatch_connect_timeout_millis",
                &self.dispatch_connect_timeout_millis,
            )
            .field(
                "dispatch_acquire_timeout_millis",
                &self.dispatch_acquire_timeout_millis,
            )
            .field(
                "dispatch_statement_timeout_millis",
                &self.dispatch_statement_timeout_millis,
            )
            .field(
                "dispatch_lock_timeout_millis",
                &self.dispatch_lock_timeout_millis,
            )
            .field(
                "provider_late_effect_bound_millis",
                &self.provider_late_effect_bound_millis,
            )
            .field(
                "provider_boundary_id",
                &self.provider_boundary_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "endpoint_host",
                &self.endpoint_host.as_ref().map(|_| "[REDACTED]"),
            )
            .field("region", &self.region.as_ref().map(|_| "[REDACTED]"))
            .field(
                "budget_revision",
                &self.budget_revision.as_ref().map(|_| "[REDACTED]"),
            )
            .field("budget_fence", &self.budget_fence)
            .field(
                "provider_write_authority_revision",
                &self
                    .provider_write_authority_revision
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

struct EnabledFragmentProviderConfig {
    dispatch_postgres_url: String,
    dispatch_ca_cert_path: String,
    dispatch_pool_max: u32,
    dispatch_connect_timeout: Duration,
    dispatch_acquire_timeout: Duration,
    dispatch_statement_timeout: Duration,
    dispatch_lock_timeout: Duration,
    provider_late_effect_bound: Duration,
    boundary: CellProviderBoundary,
    budget_pin: BudgetPin,
    provider_write_authority_revision: Option<String>,
}

/// Everything the direct server composition path must supply to activate the
/// governed fragment route.
///
/// Keeping the coordinator and exact process pool inventory in one value makes
/// partial activation unrepresentable. Generic plugin and maintenance callers
/// pass `None` and are refused before immutable-store construction when the
/// route is enabled.
pub(crate) struct FragmentProviderActivation {
    coordinator: PostgresFragmentCoordinator,
    process_pool_inventory: ValidatedFragmentProcessPoolInventory,
    expected_database_identity: DatabaseIdentity,
}

impl FragmentProviderActivation {
    pub(crate) fn new(
        coordinator: PostgresFragmentCoordinator,
        process_pool_inventory: ValidatedFragmentProcessPoolInventory,
        expected_database_identity: DatabaseIdentity,
    ) -> Self {
        Self {
            coordinator,
            process_pool_inventory,
            expected_database_identity,
        }
    }
}

const MAX_DISPATCH_POOL_MAX: u32 = 5;
const MAX_DISPATCH_TIMEOUT_MILLIS: u64 = i32::MAX as u64;

fn default_pool_max() -> u32 {
    10
}

fn default_domain_pool_max() -> u32 {
    4
}

fn default_fragment_in_flight_puts() -> u32 {
    lore_postgres::domain::fragments::DEFAULT_IN_FLIGHT_PUTS
}

fn default_fragment_put_admission_wait_millis() -> u64 {
    5_000
}

fn config_error(name: &str, message: impl Into<String>) -> PluginError {
    PluginError::from(PluginConfigError {
        plugin_name: name.to_string(),
        message: message.into(),
    })
}

fn required_string(
    name: &str,
    field: &'static str,
    value: &Option<String>,
) -> Result<String, PluginError> {
    value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            config_error(
                name,
                format!("enabled fragment_provider requires non-empty {field}"),
            )
        })
}

fn required_timeout(
    name: &str,
    field: &'static str,
    value: Option<u64>,
) -> Result<Duration, PluginError> {
    match value {
        Some(value) if (1..=MAX_DISPATCH_TIMEOUT_MILLIS).contains(&value) => {
            Ok(Duration::from_millis(value))
        }
        _ => Err(config_error(
            name,
            format!(
                "enabled fragment_provider requires {field} between 1 and \
                 {MAX_DISPATCH_TIMEOUT_MILLIS} milliseconds"
            ),
        )),
    }
}

fn required_provider_send_timeout(name: &str, value: u64) -> Result<Duration, PluginError> {
    if (1..=FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS).contains(&value) {
        Ok(Duration::from_millis(value))
    } else {
        Err(config_error(
            name,
            format!(
                "enabled fragment_provider requires object_store.timeout_millis between 1 and \
                 {FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS} milliseconds"
            ),
        ))
    }
}

fn enabled_fragment_provider_config(
    name: &str,
    cfg: &PostgresStoreConfig,
) -> Result<Option<EnabledFragmentProviderConfig>, PluginError> {
    let Some(raw) = cfg
        .fragment_provider
        .as_ref()
        .filter(|fragment_provider| fragment_provider.enabled)
    else {
        return Ok(None);
    };
    let object_store = cfg.object_store.as_ref().ok_or_else(|| {
        config_error(
            name,
            "enabled fragment_provider requires the immutable object_store configuration",
        )
    })?;
    let dispatch_pool_max = raw.dispatch_pool_max.ok_or_else(|| {
        config_error(name, "enabled fragment_provider requires dispatch_pool_max")
    })?;
    if !(1..=MAX_DISPATCH_POOL_MAX).contains(&dispatch_pool_max) {
        return Err(config_error(
            name,
            format!(
                "enabled fragment_provider requires dispatch_pool_max between 1 and \
                 {MAX_DISPATCH_POOL_MAX}"
            ),
        ));
    }
    let dispatch_postgres_url =
        required_string(name, "dispatch_postgres_url", &raw.dispatch_postgres_url)?;
    let dispatch_ca_cert_path =
        required_string(name, "dispatch_ca_cert_path", &raw.dispatch_ca_cert_path)?;
    let provider_boundary_id =
        required_string(name, "provider_boundary_id", &raw.provider_boundary_id)?;
    let endpoint_host = required_string(name, "endpoint_host", &raw.endpoint_host)?;
    let region = required_string(name, "region", &raw.region)?;
    let budget_revision = required_string(name, "budget_revision", &raw.budget_revision)?;
    let budget_fence = raw
        .budget_fence
        .ok_or_else(|| config_error(name, "enabled fragment_provider requires budget_fence"))?;
    let boundary = CellProviderBoundary::new(
        &provider_boundary_id,
        &object_store.bucket,
        &region,
        &endpoint_host,
    )
    .map_err(|error| {
        config_error(
            name,
            format!("enabled fragment_provider has an invalid provider boundary: {error}"),
        )
    })?;
    let budget_pin = BudgetPin::new(&budget_revision, budget_fence).map_err(|error| {
        config_error(
            name,
            format!("enabled fragment_provider has an invalid budget pin: {error}"),
        )
    })?;
    let provider_write_authority_revision = raw
        .provider_write_authority_revision
        .as_deref()
        .map(|revision| {
            FragmentWriteCapabilityCutover::new(revision)
                .map(|cutover| cutover.provider_write_authority_revision().to_owned())
                .map_err(|error| {
                    config_error(
                        name,
                        format!(
                            "enabled fragment_provider has an invalid provider_write_authority_revision: {error}"
                        ),
                    )
                })
        })
        .transpose()?;
    required_provider_send_timeout(name, object_store.timeout_millis)?;

    Ok(Some(EnabledFragmentProviderConfig {
        dispatch_postgres_url,
        dispatch_ca_cert_path,
        dispatch_pool_max,
        dispatch_connect_timeout: required_timeout(
            name,
            "dispatch_connect_timeout_millis",
            raw.dispatch_connect_timeout_millis,
        )?,
        dispatch_acquire_timeout: required_timeout(
            name,
            "dispatch_acquire_timeout_millis",
            raw.dispatch_acquire_timeout_millis,
        )?,
        dispatch_statement_timeout: required_timeout(
            name,
            "dispatch_statement_timeout_millis",
            raw.dispatch_statement_timeout_millis,
        )?,
        dispatch_lock_timeout: required_timeout(
            name,
            "dispatch_lock_timeout_millis",
            raw.dispatch_lock_timeout_millis,
        )?,
        provider_late_effect_bound: required_timeout(
            name,
            "provider_late_effect_bound_millis",
            raw.provider_late_effect_bound_millis,
        )?,
        boundary,
        budget_pin,
        provider_write_authority_revision,
    }))
}

/// Validates CR-031's in-flight put configuration through the same type the
/// seam itself takes, so the startup check and the runtime bound cannot drift.
fn validate_fragment_put_bound(
    name: &str,
    cfg: &PostgresStoreConfig,
) -> Result<InFlightPutBound, PluginError> {
    InFlightPutBound::new(
        cfg.fragment_in_flight_puts,
        std::time::Duration::from_millis(cfg.fragment_put_admission_wait_millis),
    )
    .map_err(|error| {
        PluginError::from(PluginConfigError {
            plugin_name: name.to_string(),
            message: format!(
                "Invalid fragment lifecycle provider admission config \
                 (fragment_in_flight_puts, fragment_put_admission_wait_millis): {error}"
            ),
        })
    })
}

fn default_slow_threshold() -> u64 {
    u64::MAX
}

fn default_timeout() -> u64 {
    5000
}

fn default_validate_bucket_on_startup() -> bool {
    true
}

/// Deserialize the shared Postgres store config **and** refuse any value in it
/// that cannot be honoured.
///
/// Every path that reads this config shape goes through here — `validate_config`
/// and all three `create()` bodies alike. That placement is the point:
/// `validate_config` is **not** on loreserver's boot path (`server.rs` reaches
/// `create()` directly, and the trait method's only callers are in
/// `settings.rs`'s own tests), so a check written only there refuses nothing at
/// startup. An earlier revision of this file made exactly that mistake and
/// claimed a startup refusal it did not perform.
fn parse_config(name: &str, config: &toml::Value) -> Result<PostgresStoreConfig, PluginError> {
    let parsed: PostgresStoreConfig = config.clone().try_into().map_err(|e| {
        PluginError::from(PluginConfigError {
            plugin_name: name.to_string(),
            message: format!("Failed to deserialize Postgres store config: {e}"),
        })
    })?;
    validate_fragment_put_bound(name, &parsed)?;
    let _ = enabled_fragment_provider_config(name, &parsed)?;
    Ok(parsed)
}

/// Whether the resolved immutable-store configuration requests the governed
/// fragment route.
///
/// This uses the same typed parse and validation as construction. Server boot
/// consults it only to preserve the legacy construction order when the block
/// is absent or disabled; enabled construction still validates the value again
/// at its real composition door.
pub(crate) fn fragment_provider_enabled(config: &toml::Value) -> Result<bool, PluginError> {
    let cfg = parse_config(PLUGIN_NAME, config)?;
    Ok(cfg
        .fragment_provider
        .as_ref()
        .is_some_and(|fragment_provider| fragment_provider.enabled))
}

/// Resolve the exact maxima of every Postgres pool an enabled fragment route
/// will coexist with.
///
/// Each input is the same effective store-specific configuration its factory
/// consumes. Parsing here therefore applies the real defaults independently:
/// the three store pools use their own `pool_max`, the domain pool uses the
/// mutable configuration's `domain_pool_max`, and dispatch uses only its
/// mandatory nested value.
pub(crate) fn fragment_process_pool_inventory(
    immutable_config: &toml::Value,
    mutable_config: &toml::Value,
    lock_config: &toml::Value,
) -> Result<Option<FragmentProcessPoolInventory>, PluginError> {
    let immutable = parse_config(PLUGIN_NAME, immutable_config)?;
    let Some(fragment_provider) = enabled_fragment_provider_config(PLUGIN_NAME, &immutable)? else {
        return Ok(None);
    };
    let mutable = parse_config(PLUGIN_NAME, mutable_config)?;
    let lock = parse_config(PLUGIN_NAME, lock_config)?;
    Ok(Some(FragmentProcessPoolInventory {
        immutable_pool_max: immutable.pool_max,
        mutable_pool_max: mutable.pool_max,
        lock_pool_max: lock.pool_max,
        domain_pool_max: mutable.domain_pool_max,
        dispatch_pool_max: fragment_provider.dispatch_pool_max,
    }))
}

/// Build the Postgres TLS settings from config: read the optional CA PEM bundle
/// and carry the verification-skip flag.
fn build_tls(name: &str, cfg: &PostgresStoreConfig) -> Result<TlsConfig, PluginError> {
    let ca_cert = match cfg.ca_cert_path.as_deref() {
        None => None,
        Some(path) => Some(std::fs::read_to_string(path).map_err(|e| {
            PluginError::from(PluginConfigError {
                plugin_name: name.to_string(),
                message: format!("Failed to read Postgres CA cert at {path}: {e}"),
            })
        })?),
    };
    Ok(TlsConfig {
        ca_cert,
        insecure_skip_verify: cfg.tls_insecure_skip_verify,
    })
}

/// Build the concrete Postgres immutable store from the plugin configuration.
///
/// Both normal server startup and offline maintenance use this path so config
/// fallback, TLS, object-store settings, and the standard AWS credential chain
/// cannot drift between them.
pub(crate) async fn connect_immutable_store(
    config: &toml::Value,
    fragment_activation: Option<FragmentProviderActivation>,
) -> Result<PostgresImmutableStore, PluginError> {
    let plugin_name = PLUGIN_NAME;
    let cfg = parse_config(plugin_name, config)?;
    let fragment_provider = enabled_fragment_provider_config(plugin_name, &cfg)?;
    let in_flight_puts = validate_fragment_put_bound(plugin_name, &cfg)?;
    let fragment_activation = match fragment_provider {
        None => None,
        Some(fragment_provider) => {
            let activation = fragment_activation.ok_or_else(|| {
                config_error(
                    plugin_name,
                    "enabled fragment_provider requires the lifecycle coordinator and exact process pool inventory",
                )
            })?;
            let expected_database_identity = FragmentDatabaseIdentity::new(
                &activation.expected_database_identity.system_identifier,
                activation.expected_database_identity.database_oid,
            )
            .map_err(|error| {
                PluginError::from(PluginInitError {
                    plugin_name: plugin_name.to_string(),
                    message: format!(
                        "Failed to bind the attested Postgres database identity for fragment_provider: {error}"
                    ),
                })
            })?;
            Some((fragment_provider, activation, expected_database_identity))
        }
    };
    let tls = build_tls(plugin_name, &cfg)?;
    let object = cfg.object_store.ok_or_else(|| {
        PluginError::from(PluginConfigError {
            plugin_name: plugin_name.to_string(),
            message: "Postgres immutable store requires an [object_store] section \
                      (bucket + endpoint/region/path-style)"
                .to_string(),
        })
    })?;
    let object = ObjectStoreSettings {
        bucket: object.bucket,
        endpoint_url: object.endpoint_url,
        region: object.region,
        force_path_style: object.force_path_style,
        slow_operation_threshold_millis: object.slow_operation_threshold_millis,
        timeout_millis: object.timeout_millis,
        validate_bucket_on_startup: object.validate_bucket_on_startup,
    };

    let store = PostgresImmutableStore::connect(&cfg.url, cfg.pool_max, &tls, object)
        .await
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to create Postgres immutable store: {e}"),
            })
        })?;
    let Some((fragment_provider, activation, expected_database_identity)) = fragment_activation
    else {
        let capability = store
            .fragment_write_capability_readiness()
            .await
            .map_err(|error| {
                PluginError::from(PluginInitError {
                    plugin_name: plugin_name.to_string(),
                    message: format!(
                        "Failed to attest the fragment write capability for the legacy route: {error}"
                    ),
                })
            })?;
        if capability.write_capability.claims_required() {
            return Err(config_error(
                plugin_name,
                "fragment write capability is claims-required; an absent or disabled fragment_provider cannot start",
            ));
        }
        return Ok(store);
    };
    let FragmentProviderActivation {
        coordinator,
        process_pool_inventory,
        expected_database_identity: _,
    } = activation;
    let readiness = coordinator.readiness().await.map_err(|error| {
        PluginError::from(PluginInitError {
            plugin_name: plugin_name.to_string(),
            message: format!("Failed to read fragment lifecycle readiness: {error}"),
        })
    })?;
    if !readiness.lifecycle_enabled {
        return Err(config_error(
            plugin_name,
            "fragment_provider is enabled but fragment lifecycle routing is disabled",
        ));
    }
    if !readiness.ready_for_lifecycle() {
        return Err(config_error(
            plugin_name,
            format!(
                "fragment_provider is enabled without complete fragment lifecycle readiness \
                 (provisioned={}, schema_version={}, backfill_state={}, cutover_at_present={}, \
                  same_database={}, sequence_headroom={}, unresolved_rows={})",
                readiness.provisioned,
                readiness.schema_version,
                readiness.backfill_state,
                readiness.cutover_at_present,
                readiness.same_database,
                readiness.sequence_headroom,
                readiness.unresolved_rows
            ),
        ));
    }
    if readiness.schema_version != FRAGMENT_SCHEMA_VERSION {
        return Err(config_error(
            plugin_name,
            format!(
                "enabled fragment_provider requires exact SCHEMA-118 revision {FRAGMENT_SCHEMA_VERSION}, found {}",
                readiness.schema_version
            ),
        ));
    }
    if let Some(required_revision) = readiness
        .write_capability
        .provider_write_authority_revision()
        && fragment_provider
            .provider_write_authority_revision
            .as_deref()
            != Some(required_revision)
    {
        return Err(config_error(
            plugin_name,
            "fragment_provider provider_write_authority_revision does not match the claims-required database capability",
        ));
    }

    // The server configuration never exposes plaintext dispatch mode. The
    // pinned-CA pool also checks that this URL says `sslmode=require`; a URL
    // using disable, prefer, or any other mode is refused before a connection.
    let dispatch_ca =
        std::fs::read_to_string(&fragment_provider.dispatch_ca_cert_path).map_err(|_| {
            config_error(
                plugin_name,
                "enabled fragment_provider could not read dispatch_ca_cert_path",
            )
        })?;
    if dispatch_ca.trim().is_empty() {
        return Err(config_error(
            plugin_name,
            "enabled fragment_provider dispatch_ca_cert_path contains no CA certificate",
        ));
    }
    let dispatch = FragmentDispatchRuntimeConfig {
        postgres_url: fragment_provider.dispatch_postgres_url,
        expected_database_identity,
        process_pool_inventory,
        connect_timeout: fragment_provider.dispatch_connect_timeout,
        acquire_timeout: fragment_provider.dispatch_acquire_timeout,
        statement_timeout: fragment_provider.dispatch_statement_timeout,
        lock_timeout: fragment_provider.dispatch_lock_timeout,
        tls: FragmentDispatchTls::PinnedRootCa(dispatch_ca),
    };

    store
        .with_fragment_provider(
            coordinator,
            fragment_provider.budget_pin,
            dispatch,
            fragment_provider.boundary,
            FragmentProviderRuntimeSettings::new(
                ProviderCapabilities::none(),
                in_flight_puts,
                fragment_provider.provider_late_effect_bound,
            ),
        )
        .await
        .map_err(|error| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to activate fragment_provider: {error}"),
            })
        })
}

/// Build the CR-029 domain coordinator from the plugin configuration.
///
/// The domain coordinator is deliberately **not** a plugin-registry store: it
/// implements `DomainTransactionStore`, not one of the three `lore-storage`
/// traits, and there is exactly one implementation. It shares the same
/// `[plugins.postgres.*]` connection shape as the three stores because CR-029's
/// whole point is that a domain transaction writes its domain rows and the
/// affected `lore_mutable` rows in **one** Postgres transaction — which is only
/// atomic if they are in one database.
pub(crate) async fn connect_domain_store(
    config: &toml::Value,
) -> Result<PostgresDomainStore, PluginError> {
    let plugin_name = PLUGIN_NAME;
    let cfg = parse_config(plugin_name, config)?;
    let tls = build_tls(plugin_name, &cfg)?;

    PostgresDomainStore::connect(&cfg.url, cfg.domain_pool_max, &tls)
        .await
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to create Postgres domain store: {e}"),
            })
        })
}

/// R-SHOULD-1: prove positively that another configured CR-007 pool addresses
/// the same physical database as the domain coordinator.
///
/// The four stores are configured as four independent URLs. Nothing today
/// checks that they resolve to one database, so same-database atomicity is a
/// configuration property rather than a checked one — and a cell misconfigured
/// across two databases would silently lose the atomicity CR-029 exists to
/// provide. This opens one short-lived pool against the *other* store's own
/// configured URL and compares `(system_identifier, database OID)`, so the
/// check is over the URL that store will actually use, not over an assumption
/// that the config sections agree.
pub(crate) async fn assert_domain_store_colocated(
    domain: &PostgresDomainStore,
    label: &'static str,
    config: &toml::Value,
) -> Result<(), PluginError> {
    let plugin_name = PLUGIN_NAME;
    let cfg = parse_config(plugin_name, config)?;
    let tls = build_tls(plugin_name, &cfg)?;

    // A tiny pool: this connection exists only to read the database identity
    // once at startup and is dropped immediately afterwards.
    let pool = lore_postgres::pool::build_pool(&cfg.url, 1, &tls).map_err(|e| {
        PluginError::from(PluginInitError {
            plugin_name: plugin_name.to_string(),
            message: format!("Failed to build {label} identity-check pool: {e}"),
        })
    })?;

    domain
        .assert_same_database(&pool, label)
        .await
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Postgres domain store is not co-located with the {label}: {e}"),
            })
        })
}

/// Factory for the Postgres-backed immutable store.
///
/// S3 object metadata is the representation authority. Postgres retains
/// lifecycle state, repository associations, and an exact rebuildable metering
/// projection.
pub struct PostgresImmutableStorePluginFactory;

impl ImmutableStorePluginFactory for PostgresImmutableStorePluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError> {
        let cfg = parse_config(self.name(), config)?;
        // The immutable store needs the object-storage sub-config; catch its
        // absence at validation time rather than at first write.
        if cfg.object_store.is_none() {
            return Err(PluginError::from(PluginConfigError {
                plugin_name: self.name().to_string(),
                message: "Postgres immutable store requires an [object_store] section \
                          (bucket + endpoint/region/path-style)"
                    .to_string(),
            }));
        }
        Ok(())
    }

    fn create(&self, config: &toml::Value) -> Result<Arc<dyn ImmutableStore>, PluginError> {
        // `create` is synchronous, but building the pool + S3 client and ensuring
        // the schema is async — drive it to completion like the AWS plugin does.
        // The future is `Box::pin`ned: building the AWS S3 client holds a large
        // `SdkConfig`/builder state that overflows the main thread's stack if
        // polled inline by `block_on` (aws.rs boxes its builder block for the
        // same reason).
        // Plugin construction runs once at startup, one plugin at a time, so
        // at most one runtime core is handed off at a time.
        #[allow(clippy::disallowed_methods)]
        let store = tokio::task::block_in_place(|| {
            runtime().block_on(Box::pin(connect_immutable_store(config, None)))
        })?;

        Ok(Arc::new(store))
    }
}

/// Factory for the Postgres-backed mutable (branch-tip CAS) store.
pub struct PostgresMutableStorePluginFactory;

impl MutableStorePluginFactory for PostgresMutableStorePluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError> {
        parse_config(self.name(), config).map(|_| ())
    }

    // Plugin construction is a synchronous startup-only trait method. The
    // runtime handoff is bounded to this one connection setup and cannot be
    // expressed as async through the plugin factory contract.
    #[allow(clippy::disallowed_methods)]
    fn create(
        &self,
        config: &toml::Value,
        _immutable_store: Arc<dyn ImmutableStore>,
        context: &crate::plugins::MutableStorePluginContext,
    ) -> Result<Arc<dyn MutableStore>, PluginError> {
        // The Postgres mutable store is standalone (branch-tip CAS needs no
        // fragment storage), so the immutable-store dependency is unused.
        let plugin_name = self.name();
        let cfg = parse_config(plugin_name, config)?;
        let tls = build_tls(plugin_name, &cfg)?;

        let enforcement = context.domain_enforcement.clone().ok_or_else(|| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message:
                    "Postgres mutable store requires the domain-enforcement construction handle"
                        .to_owned(),
            })
        })?;
        let store = tokio::task::block_in_place(|| {
            runtime().block_on(PostgresMutableStore::connect(&cfg.url, cfg.pool_max, &tls))
        })
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to create Postgres mutable store: {e}"),
            })
        })?
        .with_domain_enforcement(enforcement);

        Ok(Arc::new(store))
    }
}

/// Factory for the Postgres-backed lock store.
pub struct PostgresLockStorePluginFactory;

impl LockStorePluginFactory for PostgresLockStorePluginFactory {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError> {
        parse_config(self.name(), config).map(|_| ())
    }

    fn create(&self, config: &toml::Value) -> Result<Arc<dyn LockStore>, PluginError> {
        let plugin_name = self.name();
        let cfg = parse_config(plugin_name, config)?;
        let tls = build_tls(plugin_name, &cfg)?;

        // Plugin `create` is synchronous, but building the pool + ensuring the
        // schema is async — drive it to completion like the AWS plugin does.
        // Construction runs once at startup, one plugin at a time, so at most
        // one runtime core is handed off at a time.
        #[allow(clippy::disallowed_methods)]
        let store = tokio::task::block_in_place(|| {
            runtime().block_on(PostgresLockStore::connect(&cfg.url, cfg.pool_max, &tls))
        })
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to create Postgres lock store: {e}"),
            })
        })?;

        Ok(Arc::new(store))
    }
}

/// Registers the Postgres plugin factories with the given registry.
///
/// Auto-discovered by `build.rs` and called from the generated
/// `plugins/mod.rs::register_all_plugins`.
pub fn register(registry: &mut PluginRegistry) {
    registry.register_immutable_store_plugin(Box::new(PostgresImmutableStorePluginFactory));
    registry.register_mutable_store_plugin(Box::new(PostgresMutableStorePluginFactory));
    registry.register_lock_store_plugin(Box::new(PostgresLockStorePluginFactory));
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lore_base::types::KeyType;
    use lore_storage::Hash;
    use lore_storage::ImmutableStore;
    use lore_storage::Partition;

    use super::*;
    use crate::plugins::MutableStorePluginContext;
    use crate::settings::Settings;

    /// The `oodle` Cargo feature must reach `lore-postgres`, not only
    /// `lore-revision`.
    ///
    /// `lore-postgres`'s copy gates no codec of its own. It gates a
    /// **diagnostic**: CR-031's coordinator distinguishes a damaged payload
    /// (repairable in band) from an intact one this build has no codec for
    /// (needs a differently-built binary). A server whose codec is enabled but
    /// whose coordinator does not know it would report a perfectly decodable
    /// legacy Oodle2 object as unrepairable, sending an operator hunting for
    /// damage that is not there.
    ///
    /// Cargo cannot express "these two features move together", so this is the
    /// guard. It compiles in both configurations and fails only when the two
    /// disagree, which is exactly the drift a hand-edited feature list produces.
    #[test]
    fn the_oodle_feature_chain_reaches_lore_postgres() {
        use lore_base::types::FragmentFlags;
        use lore_postgres::domain::fragments::DecodeSupport;
        use lore_postgres::domain::fragments::decodable_encoding;

        let verdict = decodable_encoding(FragmentFlags::PayloadCompressedOodle2.bits());
        let expected = if cfg!(feature = "oodle") {
            DecodeSupport::Supported
        } else {
            DecodeSupport::RecognizedUnsupported
        };
        assert_eq!(
            verdict, expected,
            "lore-server's `oodle` feature must forward to lore-postgres/oodle; \
             without it the coordinator misreports a decodable Oodle2 object as unrepairable"
        );
    }

    // CR-031's in-flight put bound. Validation is the only live behavior here —
    // no gateway is constructed until Phase 5 — so these pin that an impossible
    // bound is refused at startup and that the default is the seam's own.

    fn immutable_config(extra: &str) -> toml::Value {
        // The extra keys go above the `[object_store]` header on purpose: a TOML
        // key after a table header belongs to that table, so appending would
        // have set `object_store.fragment_in_flight_puts` and proved nothing.
        let text = format!(
            r#"
url = "postgres://localhost/lore"
{extra}
[object_store]
bucket = "fragments"
"#
        );
        match toml::from_str(&text) {
            Ok(config) => config,
            Err(error) => panic!("fixture config must parse: {error}"),
        }
    }

    #[test]
    fn the_fragment_in_flight_put_bound_defaults_to_the_seams_own_default() {
        let parsed: PostgresStoreConfig = match immutable_config("").try_into() {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture config must deserialize: {error}"),
        };
        assert_eq!(
            parsed.fragment_in_flight_puts,
            lore_postgres::domain::fragments::DEFAULT_IN_FLIGHT_PUTS,
        );
        assert!(validate_fragment_put_bound(PLUGIN_NAME, &parsed).is_ok());
    }

    /// The bad values, and the strings that must name them.
    const IMPOSSIBLE_PUT_BOUNDS: [&str; 3] = [
        "fragment_in_flight_puts = 0",
        "fragment_in_flight_puts = 100000",
        "fragment_put_admission_wait_millis = 0",
    ];

    const ADMISSION_REFUSAL: &str = "fragment lifecycle provider admission config";

    /// `validate_config` refuses an impossible bound in every factory. The field
    /// lives on `PostgresStoreConfig`, so an operator can put it under any of
    /// the three `[plugins.postgres.*]` sections.
    #[test]
    fn an_impossible_fragment_put_bound_is_refused_by_every_validate_config() {
        type ValidateFn<'a> = &'a dyn Fn(&toml::Value) -> Result<(), PluginError>;

        let factories: [(&str, ValidateFn<'_>); 3] = [
            ("immutable", &|config| {
                PostgresImmutableStorePluginFactory.validate_config(config)
            }),
            ("mutable", &|config| {
                PostgresMutableStorePluginFactory.validate_config(config)
            }),
            ("lock", &|config| {
                PostgresLockStorePluginFactory.validate_config(config)
            }),
        ];
        for extra in IMPOSSIBLE_PUT_BOUNDS {
            let config = immutable_config(extra);
            for (label, validate) in &factories {
                let error = validate(&config)
                    .expect_err("an impossible in-flight put bound must be refused");
                assert!(
                    format!("{error}").contains(ADMISSION_REFUSAL),
                    "{extra} must be refused by name in the {label} factory, got {error}",
                );
            }
        }
    }

    /// **This is the one that matters, and it is the one that was missing.**
    ///
    /// `validate_config` is not on loreserver's boot path: `server.rs` reaches
    /// `create()` directly, and the trait method's only callers live in
    /// `settings.rs`'s own tests. A cell configured with
    /// `fragment_in_flight_puts = 0` therefore booted clean while this file's
    /// docs said it was refused at startup. The check now lives in
    /// `parse_config`, which every `create()` runs.
    ///
    /// No database is needed: the refusal happens while parsing, before any
    /// connection is attempted, which is also why it is a startup refusal
    /// rather than a first-write one. The URL below points nowhere on purpose —
    /// if the refusal ever moved after the connect, this test would hang or
    /// fail with a connection error instead of the admission message.
    #[test]
    fn an_impossible_fragment_put_bound_refuses_the_construction_path() {
        for extra in IMPOSSIBLE_PUT_BOUNDS {
            let config = immutable_config(extra);

            match PostgresLockStorePluginFactory.create(&config) {
                Err(error) => assert!(
                    format!("{error}").contains(ADMISSION_REFUSAL),
                    "{extra} must be refused by the lock store's create(), got {error}",
                ),
                Ok(_) => panic!("{extra} must not produce a lock store"),
            }

            // The immutable store's construction path is shared with offline
            // maintenance, so it is checked at that seam rather than through
            // the plugin trait's `create`, which additionally builds an S3
            // client.
            let immutable = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map(|runtime| runtime.block_on(connect_immutable_store(&config, None)));
            match immutable {
                Ok(Err(error)) => assert!(
                    format!("{error}").contains(ADMISSION_REFUSAL),
                    "{extra} must be refused by connect_immutable_store, got {error}",
                ),
                Ok(Ok(_)) => panic!("{extra} must not produce an immutable store"),
                Err(error) => panic!("the test runtime must build: {error}"),
            }
        }
    }

    #[test]
    fn a_valid_fragment_put_bound_passes_config_validation() {
        let config = immutable_config(
            "fragment_in_flight_puts = 16\nfragment_put_admission_wait_millis = 250",
        );
        assert!(
            PostgresImmutableStorePluginFactory
                .validate_config(&config)
                .is_ok()
        );
        let parsed: PostgresStoreConfig = match config.try_into() {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture config must deserialize: {error}"),
        };
        let bound = match validate_fragment_put_bound(PLUGIN_NAME, &parsed) {
            Ok(bound) => bound,
            Err(error) => panic!("a valid bound must validate: {error}"),
        };
        assert_eq!(bound.permits(), 16);
        assert_eq!(
            bound.acquire_timeout(),
            std::time::Duration::from_millis(250)
        );
    }

    #[test]
    fn heterogeneous_store_configuration_builds_the_exact_five_pool_inventory() {
        let immutable: toml::Value = toml::from_str(
            r#"
url = "postgresql://immutable@db.example/cell"
pool_max = 1
[object_store]
bucket = "fragments"
endpoint_url = "https://objects.example.com"
region = "us-test-1"
timeout_millis = 5000
[fragment_provider]
enabled = true
dispatch_postgres_url = "postgresql://dispatcher@db-alias.example/cell?sslmode=require"
dispatch_ca_cert_path = "C:/secrets/dispatch-ca.pem"
dispatch_pool_max = 5
dispatch_connect_timeout_millis = 1000
dispatch_acquire_timeout_millis = 1000
dispatch_statement_timeout_millis = 2000
dispatch_lock_timeout_millis = 3000
provider_boundary_id = "cell.primary"
endpoint_host = "objects.example.com"
region = "us-test-1"
budget_revision = "budget-v1"
budget_fence = 7
provider_late_effect_bound_millis = 60000
"#,
        )
        .expect("immutable config");
        let mutable: toml::Value = toml::from_str(
            r#"
url = "postgresql://mutable@db.example/cell"
pool_max = 2
domain_pool_max = 4
"#,
        )
        .expect("mutable config");
        let lock: toml::Value = toml::from_str(
            r#"
url = "postgresql://lock@db.example/cell"
pool_max = 3
"#,
        )
        .expect("lock config");

        let inventory = fragment_process_pool_inventory(&immutable, &mutable, &lock)
            .expect("valid inventory")
            .expect("enabled provider inventory");
        assert_eq!(
            inventory,
            FragmentProcessPoolInventory {
                immutable_pool_max: 1,
                mutable_pool_max: 2,
                lock_pool_max: 3,
                domain_pool_max: 4,
                dispatch_pool_max: 5,
            }
        );
    }

    async fn direct_client(url: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .expect("connect direct schema-state client");
        lore_base::lore_spawn!(async move {
            if let Err(error) = connection.await {
                eprintln!("direct postgres connection error: {error}");
            }
        });
        client
    }

    // `domain_pool_max` is deliberately its own knob, not inherited from
    // `pool_max` — see the field's own doc comment. These three pin that
    // independence at the config-parsing boundary.

    #[test]
    fn domain_pool_max_defaults_to_four_when_absent() {
        let config: toml::Value = toml::from_str(r#"url = "postgres://localhost/lore""#).unwrap();
        let parsed: PostgresStoreConfig = config.try_into().unwrap();

        assert_eq!(parsed.domain_pool_max, 4);
    }

    #[test]
    fn domain_pool_max_explicit_value_is_honoured() {
        let config: toml::Value = toml::from_str(
            r#"
            url = "postgres://localhost/lore"
            domain_pool_max = 20
            "#,
        )
        .unwrap();
        let parsed: PostgresStoreConfig = config.try_into().unwrap();

        assert_eq!(parsed.domain_pool_max, 20);
    }

    #[test]
    fn pool_max_alone_does_not_change_domain_pool_max() {
        let config: toml::Value = toml::from_str(
            r#"
            url = "postgres://localhost/lore"
            pool_max = 50
            "#,
        )
        .unwrap();
        let parsed: PostgresStoreConfig = config.try_into().unwrap();

        assert_eq!(parsed.pool_max, 50);
        assert_eq!(
            parsed.domain_pool_max, 4,
            "domain_pool_max must not inherit pool_max"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
    async fn configured_domain_enforcement_reaches_the_published_postgres_mutable_store() {
        let Ok(url) = std::env::var("LORE_TEST_PG_URL") else {
            eprintln!("LORE_TEST_PG_URL unset; skipping real construction-path enforcement test");
            return;
        };
        let domain_store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap domain schema");
        let direct = direct_client(&url).await;
        direct
            .execute(
                "UPDATE lore_domain_schema_state SET \
                    backfill_state=3, residue_classified=true, \
                    cutover_at=clock_timestamp(), enforcement_enabled=false, \
                    updated_at=clock_timestamp() WHERE id=1",
                &[],
            )
            .await
            .expect("make the disposable cell ready for enforcement");
        domain_store
            .enable_enforcement()
            .await
            .expect("enable enforcement through the production schema-state API");

        let mut settings: Settings = toml::from_str(include_str!("../../config/default.toml"))
            .expect("built-in settings fixture must deserialize");
        settings.mutable_store.mode = PLUGIN_NAME.to_string();
        settings.plugins.insert(
            PLUGIN_NAME.to_string(),
            toml::from_str(&format!("url = {url:?}\npool_max = 2\ndomain_pool_max = 2"))
                .expect("Postgres plugin fixture config"),
        );
        let configured = crate::domain::configure_domain_context(&settings)
            .await
            .expect("real domain-context construction path");
        assert!(
            configured.context.is_some(),
            "Postgres cell has a coordinator"
        );
        let plugin_context = MutableStorePluginContext {
            domain_enforcement: configured.mutable_enforcement,
        };
        let immutable: Arc<dyn ImmutableStore> = lore_storage::LocalImmutableStore::new(
            None,
            lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
        )
        .await
        .expect("create unused immutable-store dependency");
        let mutable = PostgresMutableStorePluginFactory
            .create(
                settings
                    .plugins
                    .get(PLUGIN_NAME)
                    .expect("Postgres plugin fixture exists"),
                immutable,
                &plugin_context,
            )
            .expect("real Postgres mutable plugin factory");

        let error = mutable
            .store(
                Partition::default(),
                Hash::from(rand::random::<[u8; 32]>()),
                Hash::from(rand::random::<[u8; 32]>()),
                KeyType::BranchLatestPointer,
            )
            .await
            .expect_err(
                "the published mutable store must share configure_domain_context's armed fence",
            );
        assert!(
            error.to_string().contains("BranchLatestPointer"),
            "fail-closed rejection must name the governed key type: {error}"
        );

        direct
            .execute(
                "UPDATE lore_domain_schema_state SET enforcement_enabled=false, \
                    updated_at=clock_timestamp() WHERE id=1",
                &[],
            )
            .await
            .expect("restore disposable schema-state enforcement flag");
    }
}
