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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lore_base::error::PluginConfigError;
use lore_base::error::PluginInitError;
use lore_base::runtime::runtime;
use lore_object_dispatch::cell_retention::CellRetentionSettings;
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
use lore_postgres::domain::fragments::InFlightChargeBound;
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
use lore_postgres::store::write_behind::WriteBehindSettings;
use lore_postgres::store::write_behind::WriteBehindStage;
use lore_postgres::store::write_behind::WriteBehindWatermarks;
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
    /// only while keeping the six-pool checked sum within budget.
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
    /// Optional WP-114 CD-7 write-behind staging tier (ADR-00027).
    ///
    /// Absence and `enabled = false` leave every PUT on the synchronous
    /// object-store path, which is also D11's fallback when an enabled tier is
    /// unavailable. Consumed only by the immutable store; the field sits on the
    /// shared connection shape for the same reason `fragment_in_flight_puts`
    /// does, so an operator who puts it under the mutable or lock section is
    /// told the value is impossible rather than that it was ignored.
    #[serde(default)]
    pub write_behind: Option<WriteBehindConfig>,
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
    /// Concurrent charge-carrying non-body attempts (HEAD, version list,
    /// delete). Separate from `fragment_in_flight_puts` because those attempts
    /// carry no object body, so CR-031's put bound never governed them.
    #[serde(default = "default_fragment_in_flight_charges")]
    pub fragment_in_flight_charges: u32,
    /// How long such an attempt waits for a slot before failing closed.
    /// Milliseconds; must be positive.
    ///
    /// This wants to be generous, not tight. One charge is issued per fragment
    /// and charges serialize per provider boundary, so the last attempt in a
    /// large push queues behind every earlier one. A wait shorter than that queue
    /// turns a pool refusal into an admission refusal and fixes nothing.
    #[serde(default = "default_fragment_charge_admission_wait_millis")]
    pub fragment_charge_admission_wait_millis: u64,
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
    /// Whether the terminal write-claim prune scheduler runs (WP-114 CD-6's
    /// hand-down from WP-118).
    ///
    /// Absent means enabled, because the governed route is the only thing that
    /// writes the claims this prunes: if that route is on, the rows accumulate,
    /// and CD-8 does not accept an unpruned evidence table. `false` is an
    /// operator taking the table's growth on deliberately, for a dark or
    /// staging cell, for a bounded time.
    pub prune_enabled: Option<bool>,
    /// Milliseconds between prune passes.
    pub prune_interval_millis: Option<u64>,
    /// Candidates one pass may plan.
    pub prune_batch: Option<u32>,
    /// How long a settled claim is kept before it becomes a candidate.
    pub prune_terminal_retention_millis: Option<u64>,
    /// Consecutive non-progressing passes that flip the prune facet false.
    pub prune_stall_ticks: Option<u32>,
    /// Whether WP-114 CD-8's cell-scale retention scheduler runs.
    ///
    /// Absent means enabled, on the same reasoning as `prune_enabled`: the
    /// governed route is the only thing that writes the dispatch evidence rows
    /// this removes, so if that route is on they accumulate, and CD-8 exists
    /// precisely to refuse an unpruned evidence table. `false` is an operator
    /// taking that growth on deliberately, for a dark or staging cell, for a
    /// bounded time.
    pub cell_retention_enabled: Option<bool>,
    /// Milliseconds between retention passes.
    pub cell_retention_interval_millis: Option<u64>,
    /// Terminal requests one retention pass may take.
    pub cell_retention_batch: Option<u32>,
    /// How long a closed request is kept before it becomes a candidate. The
    /// operator's window only: each row's own hard expiry is a separate replay
    /// floor that no value here can shorten.
    pub cell_retention_terminal_retention_millis: Option<u64>,
    /// Consecutive non-progressing passes that flip the retention facet false.
    pub cell_retention_stall_ticks: Option<u32>,
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

/// Raw optional WP-114 CD-7 write-behind staging configuration.
///
/// Every field but `enabled` stays optional at deserialization so an explicitly
/// disabled block needs only `enabled = false`.
/// [`enabled_write_behind_settings`] converts an enabled block into the store
/// crate's own [`WriteBehindSettings`] before any construction.
///
/// **There are no defaults for the thresholds, deliberately.** A defaulted
/// watermark is a guess about a filesystem this process has never seen, and the
/// consequence of guessing high is the condition C2 exists to prevent: a root
/// driven to 100% with acknowledged bytes on it. `root` has no default for the
/// reason ADR-00027 gives — a defaulted path stages onto a container's ephemeral
/// layer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteBehindConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The confined staging root. Must be absolute.
    pub root: Option<String>,
    /// The object-dispatch shared spool root. Must be absolute, and must be a
    /// **different tree** from `root`.
    ///
    /// These are two directories by owner ruling D15, not one path used twice.
    /// The spool root is fed to `SpoolLayout::new` and consumed by
    /// `bind_durable_put_body_from_ready`; `root` is ADR-00027's confined
    /// staging root. Contract C2's orphan reclaimer joins the staging tree
    /// against the epoch table and reclaims what the coordinator confirms
    /// absent — and a spool file legitimately has no epoch row, so a shared or
    /// nested tree would put in-flight upload bytes inside the reclaimer's
    /// delete set. A shared tree would also add a foreign writer under the
    /// directory `ConfinedRoot` fsyncs on every staged write.
    pub spool_root: Option<String>,
    /// Staged bytes at or below which the tier leaves its elevated state.
    pub low_bytes: Option<u64>,
    /// Staged bytes at or above which it enters the elevated state.
    pub high_bytes: Option<u64>,
    /// Staged bytes at or above which new fragments are refused.
    pub hard_bytes: Option<u64>,
    /// Staged fragment-count counterparts of the three byte thresholds.
    pub low_count: Option<u64>,
    pub high_count: Option<u64>,
    pub hard_count: Option<u64>,
    /// Free space below which new fragments are refused regardless of
    /// occupancy, so a filesystem shared with anything else cannot be driven to
    /// zero.
    pub min_free_bytes: Option<u64>,
    /// A drain heartbeat older than this selects direct fallback.
    pub drain_stale_after_millis: Option<u64>,
    /// How often the admission sampler refreshes its snapshot.
    pub sample_interval_millis: Option<u64>,
}

/// One enabled `[write_behind]` block, validated, as the two values composition
/// actually needs.
///
/// The spool root is carried beside [`WriteBehindSettings`] rather than inside
/// it because it is not the staging tier's property: `WriteBehindSettings` is
/// `lore-postgres`'s type and governs the confined staging root only. D15 made
/// the two roots distinct, so the one configuration block yields two values and
/// this is the pair.
#[derive(Debug, Clone)]
pub(crate) struct WriteBehindComposition {
    /// ADR-00027's confined staging root and its admission bounds.
    pub(crate) settings: WriteBehindSettings,
    /// The object-dispatch spool root the drain capability is minted against.
    ///
    /// Validated here and **not yet consumed by a production caller**, in the
    /// same deliberate state step 1 left `_write_behind_stage` in: WP-122's
    /// drain step is its only consumer, and inventing an interim one would mean
    /// composing a drain worker that cannot promote. The validation is the
    /// value this key has today — a cell whose two roots share a tree is
    /// refused at boot rather than discovered when contract C2's reclaimer
    /// deletes an in-flight upload. The `allow` comes off when the worker reads
    /// it; until then a `dead_code` warning here would be noise about a state
    /// that is intended and recorded.
    #[allow(
        dead_code,
        reason = "consumed by WP-122's drain worker; validated and carried until then"
    )]
    pub(crate) shared_spool_root: PathBuf,
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

fn default_fragment_in_flight_charges() -> u32 {
    lore_postgres::domain::fragments::DEFAULT_IN_FLIGHT_CHARGES
}

/// Thirty seconds: long enough to queue behind a realistic burst, short enough
/// to stay well inside the attempt-deadline horizon and to not park a read.
///
/// It was briefly 300_000, which was wrong twice over. The horizon is anchored to
/// the attempt id's own timestamp, minted BEFORE the queue, and the governed
/// client refuses a deadline beyond `attempt_ts + 300_000` — so a wait at the
/// horizon makes the shifted deadline invalid and turns a queue into a hard
/// `Internal` failure. And a HEAD on the read path has no outer timeout, so a
/// five-minute park outlives the client that asked for it and serves nobody.
/// `validate_fragment_charge_bound` now refuses any wait that cannot fit.
fn default_fragment_charge_admission_wait_millis() -> u64 {
    30_000
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

/// Upper bound on both write-behind duration knobs.
///
/// One hour, and not a tuning opinion. Each value decides how long the cell may
/// go on believing a stale picture of its own staging root, so a number large
/// enough to be a unit mistake — a milliseconds field filled in as if it were
/// seconds — is refused rather than honoured for the next eleven days.
const MAX_WRITE_BEHIND_INTERVAL_MILLIS: u64 = 3_600_000;

fn write_behind_error(name: &str, message: impl Into<String>) -> PluginError {
    let message: String = message.into();
    config_error(name, format!("enabled write_behind {message}"))
}

fn required_write_behind_u64(
    name: &str,
    field: &'static str,
    value: Option<u64>,
) -> Result<u64, PluginError> {
    value.ok_or_else(|| write_behind_error(name, format!("requires {field}")))
}

/// One required, non-empty, absolute root, named by its own configuration key.
///
/// Absoluteness is required here rather than left to canonicalization. A
/// relative path resolves against the process working directory, which is an
/// operator-invisible input, so the same configuration would address different
/// filesystems depending on how the unit was launched.
fn required_write_behind_root(
    name: &str,
    field: &'static str,
    value: Option<&str>,
) -> Result<PathBuf, PluginError> {
    let root = value
        .map(str::trim)
        .filter(|root| !root.is_empty())
        .ok_or_else(|| write_behind_error(name, format!("requires a non-empty {field}")))?;
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(write_behind_error(
            name,
            format!("requires an absolute {field}"),
        ));
    }
    Ok(root)
}

/// Turn one enabled block into the store crate's own settings type, refusing
/// every value the staging tier could not honour.
///
/// Deliberately separate from [`enabled_write_behind_settings`]'s platform and
/// coupling gates, and deliberately reached *before* them, so that every content
/// refusal below is exercised on the development rig as well as on the hosts
/// that can actually stage. A check that only ever runs on Unix is a check this
/// Windows workspace never sees fail.
fn validated_write_behind_settings(
    name: &str,
    raw: &WriteBehindConfig,
) -> Result<WriteBehindComposition, PluginError> {
    let root = required_write_behind_root(name, "root", raw.root.as_deref())?;
    let shared_spool_root =
        required_write_behind_root(name, "spool_root", raw.spool_root.as_deref())?;
    // D15: two directories, not one path used twice. Nesting is refused in both
    // directions, not just equality, because the hazard is a shared *tree*: the
    // C2 reclaimer enumerates the staging tree and deletes what the coordinator
    // confirms absent, and a spool file legitimately carries no epoch row. A
    // spool root under the staging root would therefore put in-flight upload
    // bytes in the delete set; a staging root under the spool root puts
    // acknowledged staged bytes under a foreign writer inside the tree
    // `ConfinedRoot` fsyncs on every staged write.
    //
    // This is a lexical check on two absolute paths, and it is stated as such:
    // it does not resolve symlinks, and two distinct spellings of one directory
    // pass it. That is the same limit the absolute-path rule above accepts, and
    // the alternative — resolving both roots at configuration parse time —
    // performs filesystem work inside a pure validator on a rig that may not
    // have either directory yet.
    if root == shared_spool_root
        || root.starts_with(&shared_spool_root)
        || shared_spool_root.starts_with(&root)
    {
        return Err(write_behind_error(
            name,
            "requires root and spool_root to be separate trees, neither equal to nor nested \
             inside the other",
        ));
    }

    let low_bytes = required_write_behind_u64(name, "low_bytes", raw.low_bytes)?;
    let high_bytes = required_write_behind_u64(name, "high_bytes", raw.high_bytes)?;
    let hard_bytes = required_write_behind_u64(name, "hard_bytes", raw.hard_bytes)?;
    let low_count = required_write_behind_u64(name, "low_count", raw.low_count)?;
    let high_count = required_write_behind_u64(name, "high_count", raw.high_count)?;
    let hard_count = required_write_behind_u64(name, "hard_count", raw.hard_count)?;
    let min_free_bytes = required_write_behind_u64(name, "min_free_bytes", raw.min_free_bytes)?;

    // The hysteresis latch is set at the high watermark and cleared at the low
    // one. Ordering them wrongly does not fail anywhere in the admission layer;
    // it just produces a latch that can never clear, which reads as a cell
    // permanently in direct fallback with no error anywhere to explain it.
    if low_bytes > high_bytes || high_bytes > hard_bytes {
        return Err(write_behind_error(
            name,
            "requires low_bytes <= high_bytes <= hard_bytes",
        ));
    }
    if low_count > high_count || high_count > hard_count {
        return Err(write_behind_error(
            name,
            "requires low_count <= high_count <= hard_count",
        ));
    }
    // A zero hard ceiling refuses every PUT the moment occupancy is observed at
    // all, because the comparison is `>=`. A zero free-space floor disables the
    // shared-filesystem protection outright. Neither is a configuration anyone
    // means.
    if hard_bytes == 0 || hard_count == 0 || min_free_bytes == 0 {
        return Err(write_behind_error(
            name,
            "requires positive hard_bytes, hard_count and min_free_bytes",
        ));
    }

    let drain_stale_after = required_write_behind_u64(
        name,
        "drain_stale_after_millis",
        raw.drain_stale_after_millis,
    )?;
    let sample_interval =
        required_write_behind_u64(name, "sample_interval_millis", raw.sample_interval_millis)?;
    for (field, value) in [
        ("drain_stale_after_millis", drain_stale_after),
        ("sample_interval_millis", sample_interval),
    ] {
        // The lower bound is load-bearing rather than tidy: the sampler builds
        // a `tokio::time::interval` from this value, and that constructor
        // panics on a zero period. A refusal here is the difference between a
        // configuration error and a panicking background task.
        if !(1..=MAX_WRITE_BEHIND_INTERVAL_MILLIS).contains(&value) {
            return Err(write_behind_error(
                name,
                format!("requires {field} between 1 and {MAX_WRITE_BEHIND_INTERVAL_MILLIS}"),
            ));
        }
    }

    let settings = WriteBehindSettings {
        root,
        watermarks: WriteBehindWatermarks {
            low_bytes,
            high_bytes,
            hard_bytes,
            low_count,
            high_count,
            hard_count,
            min_free_bytes,
        },
        drain_stale_after: Duration::from_millis(drain_stale_after),
        sample_interval: Duration::from_millis(sample_interval),
    };
    Ok(WriteBehindComposition {
        settings,
        shared_spool_root,
    })
}

/// Refuse a staging tier that nothing would ever consult.
///
/// The staged route lives entirely inside the coordinated PUT path: the branch
/// at `lore-postgres/src/store/immutable_store.rs:1558` is reached only with a
/// coordinator and a provider entry in hand. A legacy cell — `fragment_provider`
/// absent or `enabled = false` — would therefore attach a proven staging root,
/// run its sampler, publish its admission facet, and never stage a single byte.
///
/// That is the failure shape this package exists to refuse rather than discover:
/// inert wiring that reports healthy. It is the same refusal
/// [`crate::fragment_retention::CellRetentionWiringError::NoDispatchPool`] makes
/// for the same reason.
fn write_behind_requires_governed_route(
    name: &str,
    cfg: &PostgresStoreConfig,
) -> Result<(), PluginError> {
    if cfg
        .fragment_provider
        .as_ref()
        .is_some_and(|fragment_provider| fragment_provider.enabled)
    {
        return Ok(());
    }
    Err(write_behind_error(
        name,
        "requires an enabled fragment_provider; the staged route is reachable only from the \
         coordinated PUT path, so a legacy cell would run a staging tier that never stages",
    ))
}

/// The reviewed staging settings for this cell, or `None` when no staging tier
/// should be opened.
///
/// `None` covers both inert cases with one answer: no `write_behind` block, and
/// one that is `enabled = false`. Either leaves every PUT on the synchronous
/// object-store path.
///
/// # Refusal order
///
/// Content first, then the governed-route coupling, then the platform. The
/// platform gate is last on purpose. It is unconditional on a non-Unix host, so
/// putting it first would make every content refusal below unreachable — and
/// therefore untestable — on the rig this fork is developed on.
fn enabled_write_behind_settings(
    name: &str,
    cfg: &PostgresStoreConfig,
) -> Result<Option<WriteBehindComposition>, PluginError> {
    let Some(raw) = cfg
        .write_behind
        .as_ref()
        .filter(|write_behind| write_behind.enabled)
    else {
        return Ok(None);
    };
    let composition = validated_write_behind_settings(name, raw)?;
    write_behind_requires_governed_route(name, cfg)?;
    write_behind_platform_gate(name)?;
    Ok(Some(composition))
}

/// D13's boot-time half, on a host that can stage.
///
/// The compile-time half is `ConfinedRoot`'s own `cfg(not(unix))` module, which
/// refuses every operation. This gate is a `cfg` fork rather than a runtime
/// probe for the reason D13 gives: the difference is in directory fsync and
/// rename semantics, which a probe would have to *perform* to discover, on the
/// root it is deciding whether to trust.
#[cfg(unix)]
fn write_behind_platform_gate(_name: &str) -> Result<(), PluginError> {
    Ok(())
}

/// D13's boot-time half, on a host that cannot.
///
/// Without it an operator configures a staging tier, boots, sees a healthy
/// process, and learns the truth one failed PUT at a time.
#[cfg(not(unix))]
fn write_behind_platform_gate(name: &str) -> Result<(), PluginError> {
    Err(write_behind_error(
        name,
        "requires a Unix host; write-behind staging depends on directory fsync and rename \
         semantics this platform does not provide",
    ))
}

/// The reviewed staging settings for this cell, read from the same resolved
/// immutable-store configuration every other scheduler reads.
pub(crate) fn write_behind_settings(
    config: &toml::Value,
) -> Result<Option<WriteBehindComposition>, PluginError> {
    let cfg = parse_config(PLUGIN_NAME, config)?;
    enabled_write_behind_settings(PLUGIN_NAME, &cfg)
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

/// Validates the charge-admission configuration through the seam's own type, for
/// the same reason [`validate_fragment_put_bound`] does: the startup check and the
/// runtime bound cannot then drift apart.
fn validate_fragment_charge_bound(
    name: &str,
    cfg: &PostgresStoreConfig,
) -> Result<InFlightChargeBound, PluginError> {
    // The queue must fit inside the attempt-deadline horizon, and this is checked
    // at boot rather than hoped for. The seam shifts a queued attempt's deadline
    // forward by the time it waited, but the horizon is anchored to the attempt
    // id's own timestamp, which is minted before the wait. So if
    // wait + per-operation timeout can exceed the horizon, a sufficiently deep
    // queue yields a deadline the governed client refuses outright — a hard
    // failure, not a late success. Refusing the configuration is the only place
    // this can be caught before it costs a push.
    let horizon = FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS;
    // `timeout_millis` is the per-operation budget the caller stamps into the
    // deadline, and it lives on the optional object-store block. Absent that
    // block there is no fragment route at all, so the wait alone must fit.
    let io_timeout = cfg
        .object_store
        .as_ref()
        .map_or(0, |object_store| object_store.timeout_millis);
    let combined = cfg
        .fragment_charge_admission_wait_millis
        .saturating_add(io_timeout);
    if combined > horizon {
        return Err(PluginError::from(PluginConfigError {
            plugin_name: name.to_string(),
            message: format!(
                "fragment_charge_admission_wait_millis ({}) + object_store.timeout_millis ({}) = \
                 {} exceeds the provider attempt deadline horizon of {horizon} ms; a queued \
                 attempt would be refused for an out-of-horizon deadline instead of admitted late",
                cfg.fragment_charge_admission_wait_millis, io_timeout, combined
            ),
        }));
    }
    InFlightChargeBound::new(
        cfg.fragment_in_flight_charges,
        std::time::Duration::from_millis(cfg.fragment_charge_admission_wait_millis),
    )
    .map_err(|error| {
        PluginError::from(PluginConfigError {
            plugin_name: name.to_string(),
            message: format!(
                "Invalid fragment lifecycle provider charge-admission config \
                 (fragment_in_flight_charges, fragment_charge_admission_wait_millis): {error}"
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
    // Beside its sibling on purpose. Both fields sit on the shared
    // `PostgresStoreConfig`, so all three factories deserialize both, and the
    // put-bound field's own documentation promises that an operator who sets it
    // under the mutable or lock section is told the value is impossible rather
    // than that it was ignored. Validating only inside the immutable-store
    // construction path would have made that promise true of one field and false
    // of the other: a lock-store factory handed `fragment_in_flight_charges = 0`
    // would have proceeded to a live connection attempt and failed with a
    // connection error instead of the admission message.
    validate_fragment_charge_bound(name, &parsed)?;
    let _ = enabled_fragment_provider_config(name, &parsed)?;
    // Beside its sibling, and on the boot path rather than in `validate_config`
    // alone, for the reason this function's own documentation gives. The field
    // sits on the shared connection shape, so an operator who puts an enabled
    // `write_behind` block under the mutable or lock section is refused here
    // rather than told nothing and ignored.
    let _ = enabled_write_behind_settings(name, &parsed)?;
    Ok(parsed)
}

/// Whether the resolved immutable-store configuration requests the governed
/// fragment route.
///
/// This uses the same typed parse and validation as construction. Server boot
/// consults it only to preserve the legacy construction order when the block
/// is absent or disabled; enabled construction still validates the value again
/// at its real composition door.
/// The reviewed prune-scheduler settings for this cell, or `None` when no
/// scheduler should run.
///
/// `None` covers all three inert cases with one answer: no `fragment_provider`
/// block, one that is `enabled = false`, and one with `prune_enabled = false`.
/// The first two write no write-claims at all, so a scheduler would poll an
/// empty table forever; the third is an operator's explicit choice.
///
/// An out-of-bounds value is an `Err` here rather than a clamp, and it reaches
/// the caller on the boot path, so a cell configured with one does not come up
/// — the same treatment `fragment_in_flight_puts` gets, for the same reason.
pub(crate) fn fragment_prune_settings(
    config: &toml::Value,
) -> Result<Option<crate::fragment_prune::FragmentPruneSettings>, PluginError> {
    let cfg = parse_config(PLUGIN_NAME, config)?;
    let Some(provider) = cfg.fragment_provider.as_ref().filter(|p| p.enabled) else {
        return Ok(None);
    };
    if provider.prune_enabled == Some(false) {
        return Ok(None);
    }
    crate::fragment_prune::FragmentPruneSettings::new(
        provider.prune_interval_millis,
        provider.prune_batch,
        provider.prune_terminal_retention_millis,
        provider.prune_stall_ticks,
    )
    .map(Some)
    .map_err(|error| config_error(PLUGIN_NAME, error.to_string()))
}

/// The reviewed cell-retention settings for this cell, or `None` when no
/// retention scheduler should run.
///
/// `None` covers all three inert cases with one answer, exactly as
/// [`fragment_prune_settings`] does: no `fragment_provider` block, one that is
/// `enabled = false`, and one with `cell_retention_enabled = false`. The first
/// two opened no dispatch pool at all, so there is nothing to run a pass on;
/// the third is an operator's explicit choice.
///
/// An out-of-bounds value is an `Err` here rather than a clamp, and it reaches
/// the caller on the boot path, so a cell configured with one does not come up.
pub(crate) fn cell_retention_settings(
    config: &toml::Value,
) -> Result<Option<CellRetentionSettings>, PluginError> {
    let cfg = parse_config(PLUGIN_NAME, config)?;
    let Some(provider) = cfg.fragment_provider.as_ref().filter(|p| p.enabled) else {
        return Ok(None);
    };
    if provider.cell_retention_enabled == Some(false) {
        return Ok(None);
    }
    CellRetentionSettings::new(
        provider.cell_retention_interval_millis,
        provider.cell_retention_batch,
        provider.cell_retention_terminal_retention_millis,
        provider.cell_retention_stall_ticks,
    )
    .map(Some)
    .map_err(|error| config_error(PLUGIN_NAME, error.to_string()))
}

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
/// `relay_enabled` comes from `[outbox_relay]`, which lives in `Settings`
/// rather than in any store's own configuration, so composition passes it in.
/// It decides presence, not size: CR-032's relay opens exactly
/// `RELAY_POOL_MAX` connections when it runs and none at all when it does not,
/// and reserving for a pool the process never opens would refuse cells that are
/// genuinely inside the budget.
/// The inventory is built for every Postgres-mode process, not only one with a
/// fragment provider. The four store and domain pools open either way, and so
/// does CR-032's relay pool when `[outbox_relay]` is enabled, so a
/// provider-disabled cell holds real connections against the same ceiling. It
/// previously escaped the ceiling entirely, because the inventory that carries
/// the arithmetic was only built on the provider path.
///
/// `dispatch_pool_max` is therefore zero when no provider is configured, with
/// the same meaning `relay_pool_max` zero has: this process does not open that
/// pool. It is never inferred — an enabled provider must declare its own.
pub(crate) fn fragment_process_pool_inventory(
    immutable_config: &toml::Value,
    mutable_config: &toml::Value,
    lock_config: Option<&toml::Value>,
    relay_enabled: bool,
) -> Result<FragmentProcessPoolInventory, PluginError> {
    let immutable = parse_config(PLUGIN_NAME, immutable_config)?;
    let mutable = parse_config(PLUGIN_NAME, mutable_config)?;
    // `None` is a lock store that is not in Postgres mode: the pool is absent
    // rather than undeclared, the same way an absent provider or relay is.
    let lock_pool_max = match lock_config {
        Some(config) => parse_config(PLUGIN_NAME, config)?.pool_max,
        None => 0,
    };
    let dispatch_pool_max = enabled_fragment_provider_config(PLUGIN_NAME, &immutable)?
        .map_or(0, |fragment_provider| fragment_provider.dispatch_pool_max);
    Ok(FragmentProcessPoolInventory {
        immutable_pool_max: immutable.pool_max,
        mutable_pool_max: mutable.pool_max,
        lock_pool_max,
        domain_pool_max: mutable.domain_pool_max,
        dispatch_pool_max,
        relay_pool_max: if relay_enabled {
            crate::event_relay::RELAY_POOL_MAX
        } else {
            0
        },
    })
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

/// Open only the read-only object namespace inspector for offline initialization.
/// The enabled provider and authority revision must match the future serving route.
pub(crate) async fn connect_clean_namespace_inspector(
    config: &toml::Value,
    authority_revision: &str,
) -> Result<
    lore_postgres::store::immutable_store::clean_namespace::CleanObjectNamespaceInspector,
    PluginError,
> {
    let cfg = parse_config(PLUGIN_NAME, config)?;
    let provider = enabled_fragment_provider_config(PLUGIN_NAME, &cfg)?.ok_or_else(|| {
        config_error(
            PLUGIN_NAME,
            "clean initialization requires enabled fragment_provider",
        )
    })?;
    if provider.provider_write_authority_revision.as_deref() != Some(authority_revision) {
        return Err(config_error(
            PLUGIN_NAME,
            "clean initialization authority revision must match fragment_provider.provider_write_authority_revision",
        ));
    }
    validate_fragment_put_bound(PLUGIN_NAME, &cfg)?;
    let object = cfg
        .object_store
        .ok_or_else(|| config_error(PLUGIN_NAME, "clean initialization requires object_store"))?;
    lore_postgres::store::immutable_store::clean_namespace::CleanObjectNamespaceInspector::connect(
        ObjectStoreSettings {
            bucket: object.bucket,
            endpoint_url: object.endpoint_url,
            region: object.region,
            force_path_style: object.force_path_style,
            slow_operation_threshold_millis: object.slow_operation_threshold_millis,
            timeout_millis: object.timeout_millis,
            validate_bucket_on_startup: object.validate_bucket_on_startup,
        },
    )
    .await
    .map_err(|error| config_error(PLUGIN_NAME, error.to_string()))
}

/// Build the concrete Postgres immutable store from the plugin configuration.
///
/// Both normal server startup and offline maintenance use this path so config
/// fallback, TLS, object-store settings, and the standard AWS credential chain
/// cannot drift between them.
///
/// `write_behind` is the already-opened staging tier, or `None` for every cell
/// and every caller that composes none. It arrives as a parameter rather than
/// being opened here because the composing server must keep its own handle:
/// `note_pending_staged` and `note_drain_heartbeat` have to be driven
/// repeatedly from a recurring task, and a stage this function opened and gave
/// away would leave that half with no owner.
pub(crate) async fn connect_immutable_store(
    config: &toml::Value,
    fragment_activation: Option<FragmentProviderActivation>,
    write_behind: Option<Arc<WriteBehindStage>>,
) -> Result<PostgresImmutableStore, PluginError> {
    let plugin_name = PLUGIN_NAME;
    let cfg = parse_config(plugin_name, config)?;
    let fragment_provider = enabled_fragment_provider_config(plugin_name, &cfg)?;
    let in_flight_puts = validate_fragment_put_bound(plugin_name, &cfg)?;
    let in_flight_charges = validate_fragment_charge_bound(plugin_name, &cfg)?;
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

    // Compute without a second SDK client or provider call. Legacy cells do not
    // require explicit namespace fields, so defer any refusal until clean state.
    let configured_clean_namespace =
        lore_postgres::store::immutable_store::clean_namespace::clean_namespace_identity(&object);
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
        // Unreachable through the configuration path — an enabled
        // `write_behind` block requires an enabled `fragment_provider`, and an
        // enabled provider with no activation is refused above — and refused
        // rather than assumed away. Attaching a stage here would give the cell
        // a proven staging root, a running sampler and a healthy-looking
        // admission facet on a route that never stages.
        if write_behind.is_some() {
            return Err(config_error(
                plugin_name,
                "write_behind cannot be attached to the legacy fragment route",
            ));
        }
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

    if readiness.clean_initialized {
        let identity = configured_clean_namespace
            .map_err(|error| config_error(plugin_name, error.to_string()))?;
        let revision = fragment_provider
            .provider_write_authority_revision
            .as_ref()
            .ok_or_else(|| {
                config_error(
                    plugin_name,
                    "clean initialized fragment route requires a provider authority revision",
                )
            })?;
        let input = lore_postgres::domain::fragments::initialization::CleanCellInitialization::new(
            identity,
            revision.clone(),
        )
        .map_err(|error| {
            config_error(
                plugin_name,
                format!("invalid clean initialization binding: {error}"),
            )
        })?;
        let completed = coordinator
            .initialization_status(&input)
            .await
            .map_err(|error| {
                config_error(
                    plugin_name,
                    format!("clean fragment namespace attestation failed: {error}"),
                )
            })?;
        if !completed {
            return Err(config_error(
                plugin_name,
                "clean fragment namespace has no matching completed initialization",
            ));
        }
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

    // Attached before the provider route is activated, so no PUT can observe a
    // coordinated store whose staging tier is still half-composed.
    // `with_write_behind` sets the staged-epoch cleanup collaborator from the
    // same `Arc`, which is why there is one call and not two.
    let store = match write_behind {
        Some(stage) => store.with_write_behind(stage),
        None => store,
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
                in_flight_charges,
                fragment_provider.provider_late_effect_bound,
                fragment_provider.provider_write_authority_revision,
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

/// Build the concrete Postgres mutable store from the plugin configuration.
///
/// Offline maintenance needs the same store normal startup publishes behind
/// `Arc<dyn MutableStore>`: WP-120's `loreserver domain cutover` reads the
/// cell's real repositories and branches through `lore-revision`, which reaches
/// them through this trait. Built through the shared `parse_config`/`build_tls`
/// path so the connection shape and TLS material cannot drift from the serving
/// one — a maintenance command that reached a different database than the
/// server would arm a cell nobody is serving.
///
/// `ensure_schema` runs here as it does at startup, which is also why the
/// cutover command opens this store *before* the domain backfill's verification:
/// that verification reads `lore_mutable`, and this is what creates it.
pub(crate) async fn connect_mutable_store(
    config: &toml::Value,
) -> Result<PostgresMutableStore, PluginError> {
    let plugin_name = PLUGIN_NAME;
    let cfg = parse_config(plugin_name, config)?;
    let tls = build_tls(plugin_name, &cfg)?;

    PostgresMutableStore::connect(&cfg.url, cfg.pool_max, &tls)
        .await
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to create Postgres mutable store: {e}"),
            })
        })
}

/// Build a small dedicated pool on the cell database for CR-032's relay worker
/// (WP-119 Step B).
///
/// It reuses the `[plugins.postgres]` connection shape and TLS material rather
/// than adding a second URL, for the same reason the domain coordinator does:
/// the outbox rows the relay reads are written by mutation transactions in that
/// exact database, and a second URL would make co-location a configuration
/// property again. The caller still proves co-location positively before
/// running anything; this function only builds the pool.
pub(crate) fn connect_relay_pool(
    config: &toml::Value,
    pool_max: u32,
) -> Result<lore_postgres::pool::Pool, PluginError> {
    let plugin_name = PLUGIN_NAME;
    let cfg = parse_config(plugin_name, config)?;
    let tls = build_tls(plugin_name, &cfg)?;
    lore_postgres::pool::build_pool(&cfg.url, pool_max, &tls).map_err(|e| {
        PluginError::from(PluginInitError {
            plugin_name: plugin_name.to_string(),
            message: format!("Failed to build the outbox relay pool: {e}"),
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
            runtime().block_on(Box::pin(connect_immutable_store(config, None, None)))
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
    warn_if_fragment_failpoints_are_compiled();
    registry.register_immutable_store_plugin(Box::new(PostgresImmutableStorePluginFactory));
    registry.register_mutable_store_plugin(Box::new(PostgresMutableStorePluginFactory));
    registry.register_lock_store_plugin(Box::new(PostgresLockStorePluginFactory));
}

/// The boot banner emitted when this binary carries WP-118 Phase 9's fragment
/// failpoints. Named so a test can assert on the exact bytes.
pub(crate) const FRAGMENT_FAILPOINTS_COMPILED_BANNER: &str = "WARNING: this loreserver was built with `failure_generator`. The fragment lifecycle \
     coordinator carries WP-118 Phase 9 failpoints, which can pause, abort, or withhold a commit \
     acknowledgement when LORE_FRAGMENT_FAILPOINTS names an anchor. This is a TEST binary and \
     must not serve production traffic.";

/// Announce at boot that this binary carries WP-118 Phase 9's fragment
/// failpoints.
///
/// Every other guard on this feature is compile-time: the module does not exist
/// in a default build, so no failpoint can fire in one. This covers the case
/// those guards cannot — a binary that really was built with the feature and
/// then deployed. `ServerInfo` already reports `failure_generator`, but only to
/// a client that asks; and `failpoints.rs` warns only once at least one anchor
/// parses, so a feature-carrying binary with no environment set is otherwise
/// silent.
///
/// **Written to stderr rather than through `tracing`, and that is not a style
/// choice.** [`register`] is reached from `server.rs`'s `register_all_plugins`
/// call, which runs *before* `TelemetryInitializer::init` installs a subscriber
/// — deliberately, so every compiled-in plugin can contribute OpenTelemetry
/// resource detectors first (see the comment above that call). A
/// `tracing::warn!` here is therefore emitted with no subscriber attached and is
/// dropped on the floor: it would look like coverage of the one case the
/// compile-time guards cannot reach, while covering nothing. Moving the
/// emission later would mean reordering a boot sequence whose order is
/// load-bearing for a different reason. `eprintln!` needs no subscriber, so the
/// banner survives the ordering instead of depending on it.
///
/// Keyed off the compiled-in constant rather than a local `cfg!`, so it reports
/// what `lore-postgres` actually built — the thing that matters, and the thing a
/// broken feature chain gets wrong.
fn warn_if_fragment_failpoints_are_compiled() {
    if lore_postgres::domain::fragments::failpoints_compiled() {
        eprintln!("{FRAGMENT_FAILPOINTS_COMPILED_BANNER}");
    }
}

#[cfg(test)]
#[path = "../../tests/common/clean_init_construction.rs"]
mod clean_init_construction_tests;

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

    /// The `failure_generator` Cargo feature must reach `lore-postgres`, not
    /// only `lore-storage`.
    ///
    /// WP-118 Phase 9's failpoints live in `lore-postgres`'s fragment lifecycle
    /// coordinator, and WP-109's two-process proof drives its races through
    /// them. If `lore-server/failure_generator` forwarded only to
    /// `lore-storage`, the coordinator's failpoint module would not be
    /// compiled: every `LORE_FRAGMENT_FAILPOINTS` anchor would be a silent
    /// no-op, and the proof would report green having raced nothing. That is a
    /// worse failure than a build error, because it looks like evidence.
    ///
    /// Env marker that turns a re-executed copy of this test binary into the
    /// child half of [`the_failpoint_boot_banner_actually_reaches_stderr`].
    const BANNER_CHILD_MARKER: &str = "LORE_TEST_FRAGMENT_FAILPOINT_BANNER_CHILD";

    /// The boot banner must actually be emitted, not merely be present in
    /// source.
    ///
    /// This is an executed proof on purpose. The previous version of this
    /// warning used `tracing::warn!` and was correct-looking, unreachable, and
    /// shipped: `register_all_plugins` runs before the telemetry subscriber is
    /// installed, so the event went nowhere. A source-ordering argument is what
    /// produced that defect, so it cannot be what closes it.
    ///
    /// The child re-executes this same test binary with a marker in its
    /// environment, runs the real [`register_all_plugins`] path against a fresh
    /// registry, and exits. The parent asserts on its stderr — which needs no
    /// subscriber, no configuration file, and no server boot.
    ///
    /// It asserts in **both** directions: the banner is present in a
    /// `failure_generator` build and absent in a default one. The second half
    /// is what pins that an ordinary production binary stays silent.
    #[test]
    fn the_failpoint_boot_banner_actually_reaches_stderr() {
        if std::env::var(BANNER_CHILD_MARKER).is_ok() {
            // Child: exercise the real registration path and let the banner (if
            // this build has one) go to the inherited stderr.
            let mut registry = crate::plugins::PluginRegistry::new();
            crate::plugins::register_all_plugins(&mut registry);
            return;
        }

        let exe = std::env::current_exe().expect("the test binary must know its own path");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "plugins::postgres::tests::the_failpoint_boot_banner_actually_reaches_stderr",
                "--nocapture",
            ])
            .env(BANNER_CHILD_MARKER, "1")
            .output()
            .expect("the child test process must run");
        let stderr = String::from_utf8_lossy(&output.stderr);

        if cfg!(feature = "failure_generator") {
            assert!(
                stderr.contains(FRAGMENT_FAILPOINTS_COMPILED_BANNER),
                "a failure_generator build must announce its failpoints on stderr at plugin \
                 registration, because that runs before any tracing subscriber exists. \
                 stderr was:\n{stderr}"
            );
        } else {
            assert!(
                !stderr.contains("failure_generator"),
                "a default build must not announce failpoints it does not carry. \
                 stderr was:\n{stderr}"
            );
        }
    }

    /// Second instance of the same guard shape as the `oodle` chain above, for
    /// the same reason: Cargo cannot express "these two features move
    /// together", so a hand-edited feature list is the drift and a test
    /// compiled in both configurations is the only thing that sees it.
    #[test]
    fn the_failpoint_feature_chain_reaches_lore_postgres() {
        assert_eq!(
            lore_postgres::domain::fragments::failpoints_compiled(),
            cfg!(feature = "failure_generator"),
            "lore-server's `failure_generator` feature must forward to \
             lore-postgres/failure_generator; without it WP-109's failpoints are inert and its \
             barriers race nothing"
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
                .map(|runtime| runtime.block_on(connect_immutable_store(&config, None, None)));
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

    // The charge-admission bound (CR-033 charge authority pool exhaustion).
    // Same fixture shape as the in-flight-put-bound tests directly above --
    // `fragment_in_flight_charges`/`fragment_charge_admission_wait_millis` sit
    // on the same shared `PostgresStoreConfig`.

    #[test]
    fn the_fragment_in_flight_charge_bound_defaults_to_the_seams_own_default() {
        let parsed: PostgresStoreConfig = match immutable_config("").try_into() {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture config must deserialize: {error}"),
        };
        assert_eq!(
            parsed.fragment_in_flight_charges,
            lore_postgres::domain::fragments::DEFAULT_IN_FLIGHT_CHARGES,
        );
        assert!(validate_fragment_charge_bound(PLUGIN_NAME, &parsed).is_ok());
    }

    /// The bad values, and the strings that must name them.
    const IMPOSSIBLE_CHARGE_BOUNDS: [&str; 3] = [
        "fragment_in_flight_charges = 0",
        "fragment_in_flight_charges = 100000",
        "fragment_charge_admission_wait_millis = 0",
    ];

    const CHARGE_ADMISSION_REFUSAL: &str = "fragment lifecycle provider charge-admission config";

    /// Mirrors `an_impossible_fragment_put_bound_is_refused_by_every_validate_config`
    /// exactly. The field lives on the same `PostgresStoreConfig` as the put
    /// bound, so the same claim -- any of the three `[plugins.postgres.*]`
    /// sections gets refused by name -- should hold for it too.
    #[test]
    fn an_impossible_fragment_charge_bound_is_refused_by_every_validate_config() {
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
        for extra in IMPOSSIBLE_CHARGE_BOUNDS {
            let config = immutable_config(extra);
            for (label, validate) in &factories {
                let error = validate(&config)
                    .expect_err("an impossible in-flight charge bound must be refused");
                assert!(
                    format!("{error}").contains(CHARGE_ADMISSION_REFUSAL),
                    "{extra} must be refused by name in the {label} factory, got {error}",
                );
            }
        }
    }

    /// Mirrors `an_impossible_fragment_put_bound_refuses_the_construction_path`:
    /// the lock store's `create()` (no database needed -- the URL points
    /// nowhere) and the immutable store's shared `connect_immutable_store`
    /// path must both refuse before any connection is attempted.
    #[test]
    fn an_impossible_fragment_charge_bound_refuses_the_construction_path() {
        for extra in IMPOSSIBLE_CHARGE_BOUNDS {
            let config = immutable_config(extra);

            match PostgresLockStorePluginFactory.create(&config) {
                Err(error) => assert!(
                    format!("{error}").contains(CHARGE_ADMISSION_REFUSAL),
                    "{extra} must be refused by the lock store's create(), got {error}",
                ),
                Ok(_) => panic!("{extra} must not produce a lock store"),
            }

            let immutable = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map(|runtime| runtime.block_on(connect_immutable_store(&config, None, None)));
            match immutable {
                Ok(Err(error)) => assert!(
                    format!("{error}").contains(CHARGE_ADMISSION_REFUSAL),
                    "{extra} must be refused by connect_immutable_store, got {error}",
                ),
                Ok(Ok(_)) => panic!("{extra} must not produce an immutable store"),
                Err(error) => panic!("the test runtime must build: {error}"),
            }
        }
    }

    #[test]
    fn a_valid_fragment_charge_bound_passes_config_validation() {
        let config = immutable_config(
            "fragment_in_flight_charges = 8\nfragment_charge_admission_wait_millis = 1500",
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
        let bound = match validate_fragment_charge_bound(PLUGIN_NAME, &parsed) {
            Ok(bound) => bound,
            Err(error) => panic!("a valid bound must validate: {error}"),
        };
        assert_eq!(bound.permits(), 8);
        assert_eq!(
            bound.acquire_timeout(),
            std::time::Duration::from_millis(1500)
        );
    }

    // The horizon guard (`validate_fragment_charge_bound`'s own refusal, on top
    // of the impossible-bound checks above): `fragment_charge_admission_wait_millis`
    // plus `object_store.timeout_millis` must fit inside
    // `FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS`, because `admit_operation`
    // shifts a queued attempt's deadline forward by exactly the wait, but the
    // horizon is anchored to the attempt id's timestamp minted before that
    // wait. `immutable_config`'s object-store block always deserializes with
    // the seam's own `default_timeout()` (5_000ms) for `timeout_millis`, so
    // these three pin the sum at, one over, and without that contribution at
    // all.

    #[test]
    fn a_fragment_charge_bound_exactly_at_the_deadline_horizon_passes_config_validation() {
        let wait_millis = FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS - default_timeout();
        let config = immutable_config(&format!(
            "fragment_charge_admission_wait_millis = {wait_millis}"
        ));
        let parsed: PostgresStoreConfig = match config.try_into() {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture config must deserialize: {error}"),
        };
        assert_eq!(
            parsed
                .object_store
                .as_ref()
                .map(|object_store| object_store.timeout_millis),
            Some(default_timeout()),
            "fixture must exercise the seam's own default object_store timeout"
        );
        assert_eq!(
            wait_millis + default_timeout(),
            FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS,
            "fixture arithmetic must land exactly on the horizon"
        );
        assert!(
            validate_fragment_charge_bound(PLUGIN_NAME, &parsed).is_ok(),
            "a combination exactly equal to the horizon must be admitted, not refused"
        );
    }

    #[test]
    fn a_fragment_charge_bound_one_millisecond_over_the_horizon_is_refused_naming_both_keys() {
        let wait_millis = FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS - default_timeout() + 1;
        let config = immutable_config(&format!(
            "fragment_charge_admission_wait_millis = {wait_millis}"
        ));
        let parsed: PostgresStoreConfig = match config.try_into() {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture config must deserialize: {error}"),
        };
        let error = validate_fragment_charge_bound(PLUGIN_NAME, &parsed)
            .expect_err("one millisecond over the horizon must be refused");
        let message = format!("{error}");
        assert!(
            message.contains("fragment_charge_admission_wait_millis"),
            "error must name fragment_charge_admission_wait_millis, got {message}"
        );
        assert!(
            message.contains("object_store.timeout_millis"),
            "error must name object_store.timeout_millis, got {message}"
        );
    }

    /// An absent `[object_store]` block contributes 0 to the horizon sum, not
    /// some other default. Pinned by proving the full horizon is still
    /// admissible as a wait alone when the block is entirely absent -- if
    /// absence contributed any nonzero amount (e.g. the seam's own
    /// `default_timeout()`), this combination would be refused.
    #[test]
    fn an_absent_object_store_block_contributes_zero_to_the_charge_bound_horizon_sum() {
        let text = format!(
            "url = \"postgres://localhost/lore\"\n\
             fragment_charge_admission_wait_millis = {FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS}\n"
        );
        let config: toml::Value = match toml::from_str(&text) {
            Ok(config) => config,
            Err(error) => panic!("fixture config must parse: {error}"),
        };
        let parsed: PostgresStoreConfig = match config.try_into() {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture config must deserialize: {error}"),
        };
        assert!(
            parsed.object_store.is_none(),
            "fixture must exercise the truly-absent case, not a present-but-default block"
        );
        assert!(
            validate_fragment_charge_bound(PLUGIN_NAME, &parsed).is_ok(),
            "a wait equal to the full horizon must be admitted when object_store is absent, \
             proving the absent block contributes 0 to the sum rather than some nonzero default"
        );
    }

    /// `fragment_in_flight_charges`/`fragment_charge_admission_wait_millis`
    /// live on the shared `PostgresStoreConfig`, not on
    /// `FragmentProviderConfig` -- which is `#[serde(deny_unknown_fields)]`.
    /// Putting either key under `[fragment_provider]` instead of the
    /// top-level table must be a hard deserialization refusal naming the
    /// misplaced key, not a silently-ignored value.
    #[test]
    fn a_charge_bound_key_under_fragment_provider_is_an_unknown_field() {
        let config = enabled_fragment_provider_config("fragment_in_flight_charges = 8");
        let parsed: Result<PostgresStoreConfig, _> = config.try_into();
        let error = match parsed {
            Err(error) => error,
            Ok(_) => {
                panic!("fragment_in_flight_charges under [fragment_provider] must not deserialize")
            }
        };
        assert!(
            format!("{error}").contains("fragment_in_flight_charges"),
            "the deserialization error must name the misplaced key, got {error}",
        );
    }

    // WP-114 CD-6/CD-8's settings-mapping wiring. `fragment_prune_settings` and
    // `cell_retention_settings` are `pub(crate)`, so nothing outside this file
    // can exercise them directly; both are covered here, in the same fixture
    // style as the in-flight-put-bound tests above. Neither had a same-file
    // unit test before this pass (`fragment_prune_settings` had none at all).

    /// A fully valid, `enabled = true` `[fragment_provider]` block (every
    /// field `enabled_fragment_provider_config` requires, mirroring
    /// `heterogeneous_store_configuration_builds_the_exact_five_pool_inventory`'s
    /// fixture below), with `extra` appended inside that same table.
    ///
    /// `parse_config` runs `enabled_fragment_provider_config` unconditionally
    /// once `enabled = true`, regardless of which sub-feature a test actually
    /// means to exercise, so a prune/retention-only test still needs every
    /// dispatch/boundary/budget key present or it fails on
    /// `dispatch_pool_max` before ever reaching the field under test.
    fn enabled_fragment_provider_config(extra: &str) -> toml::Value {
        let text = format!(
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
{extra}
"#
        );
        match toml::from_str(&text) {
            Ok(config) => config,
            Err(error) => panic!("fixture config must parse: {error}"),
        }
    }

    #[test]
    fn fragment_prune_settings_is_none_when_fragment_provider_is_absent() {
        let config = immutable_config("");
        assert!(
            fragment_prune_settings(&config)
                .expect("must not error")
                .is_none()
        );
    }

    #[test]
    fn fragment_prune_settings_is_none_when_fragment_provider_is_disabled() {
        let config = immutable_config("[fragment_provider]\nenabled = false\n");
        assert!(
            fragment_prune_settings(&config)
                .expect("must not error")
                .is_none()
        );
    }

    #[test]
    fn fragment_prune_settings_is_none_when_prune_enabled_is_false() {
        let config = enabled_fragment_provider_config("prune_enabled = false");
        assert!(
            fragment_prune_settings(&config)
                .expect("must not error")
                .is_none()
        );
    }

    /// `prune_enabled` omitted (as opposed to explicitly `false`) means
    /// enabled, and every other key omitted takes the scheduler's own
    /// defaults.
    #[test]
    fn fragment_prune_settings_defaults_when_enabled_with_no_other_keys() {
        let config = enabled_fragment_provider_config("");
        let settings = fragment_prune_settings(&config)
            .expect("must not error")
            .expect("an enabled block with no prune_enabled must produce settings");
        assert_eq!(
            settings,
            crate::fragment_prune::FragmentPruneSettings::default()
        );
    }

    /// Every explicit key lands on the field its name says, not a
    /// transposed neighbor.
    #[test]
    fn fragment_prune_settings_threads_explicit_values_in_the_right_positions() {
        let config = enabled_fragment_provider_config(
            "prune_interval_millis = 5000\nprune_batch = 77\n\
             prune_terminal_retention_millis = 90000\nprune_stall_ticks = 5",
        );
        let settings = fragment_prune_settings(&config)
            .expect("must not error")
            .expect("enabled settings must produce a value");
        assert_eq!(settings.interval, Duration::from_millis(5_000));
        assert_eq!(settings.batch, 77);
        assert_eq!(settings.terminal_retention, Duration::from_millis(90_000));
        assert_eq!(settings.stall_ticks, 5);
    }

    /// Each out-of-bounds key is refused, and named by its own field --
    /// proves the four constructor arguments were not transposed en route
    /// from the parsed config to `FragmentPruneSettings::new`.
    #[test]
    fn fragment_prune_settings_out_of_bounds_values_name_their_own_field() {
        let cases = [
            (
                "prune_interval_millis = 999",
                "fragment_provider.prune_interval_millis",
            ),
            ("prune_batch = 0", "fragment_provider.prune_batch"),
            (
                "prune_terminal_retention_millis = 0",
                "fragment_provider.prune_terminal_retention_millis",
            ),
            (
                "prune_stall_ticks = 0",
                "fragment_provider.prune_stall_ticks",
            ),
        ];
        for (bad_key, expected_field) in cases {
            let config = enabled_fragment_provider_config(bad_key);
            let error =
                fragment_prune_settings(&config).expect_err(&format!("{bad_key} must be refused"));
            assert!(
                error.to_string().contains(expected_field),
                "{bad_key} must be refused by name ({expected_field}), got {error}"
            );
        }
    }

    #[test]
    fn cell_retention_settings_is_none_when_fragment_provider_is_absent() {
        let config = immutable_config("");
        assert!(
            cell_retention_settings(&config)
                .expect("must not error")
                .is_none()
        );
    }

    #[test]
    fn cell_retention_settings_is_none_when_fragment_provider_is_disabled() {
        let config = immutable_config("[fragment_provider]\nenabled = false\n");
        assert!(
            cell_retention_settings(&config)
                .expect("must not error")
                .is_none()
        );
    }

    /// Distinct from an absent `fragment_provider` block and from omitting
    /// the key entirely: an operator's explicit opt-out, which
    /// `cell_retention_settings` checks with `== Some(false)`, not a falsy
    /// coercion of `Option<bool>`.
    #[test]
    fn cell_retention_settings_is_none_when_cell_retention_enabled_is_false() {
        let config = enabled_fragment_provider_config("cell_retention_enabled = false");
        assert!(
            cell_retention_settings(&config)
                .expect("must not error")
                .is_none()
        );
    }

    /// `cell_retention_enabled` omitted means enabled, on the same reasoning
    /// as `prune_enabled` above, and every other key omitted takes
    /// `CellRetentionSettings`' own defaults.
    #[test]
    fn cell_retention_settings_defaults_when_enabled_with_no_other_keys() {
        let config = enabled_fragment_provider_config("");
        let settings = cell_retention_settings(&config)
            .expect("must not error")
            .expect("an enabled block with no cell_retention_enabled must produce settings");
        assert_eq!(settings, CellRetentionSettings::default());
    }

    /// Every explicit key lands on the field its name says, not a
    /// transposed neighbor.
    #[test]
    fn cell_retention_settings_threads_explicit_values_in_the_right_positions() {
        let config = enabled_fragment_provider_config(
            "cell_retention_enabled = true\ncell_retention_interval_millis = 5000\n\
             cell_retention_batch = 50\ncell_retention_terminal_retention_millis = 120000\n\
             cell_retention_stall_ticks = 4",
        );
        let settings = cell_retention_settings(&config)
            .expect("must not error")
            .expect("enabled settings must produce a value");
        assert_eq!(settings.interval, Duration::from_millis(5_000));
        assert_eq!(settings.batch, 50);
        assert_eq!(settings.terminal_retention, Duration::from_millis(120_000));
        assert_eq!(settings.stall_ticks, 4);
    }

    /// Each out-of-bounds key is refused, and named by its own field --
    /// proves the four constructor arguments were not transposed en route
    /// from the parsed config to `CellRetentionSettings::new`.
    #[test]
    fn cell_retention_settings_out_of_bounds_values_name_their_own_field() {
        let cases = [
            (
                "cell_retention_interval_millis = 999",
                "cell_retention.interval_millis",
            ),
            ("cell_retention_batch = 0", "cell_retention.batch"),
            (
                "cell_retention_terminal_retention_millis = 0",
                "cell_retention.terminal_retention_millis",
            ),
            (
                "cell_retention_stall_ticks = 0",
                "cell_retention.stall_ticks",
            ),
        ];
        for (bad_key, expected_field) in cases {
            let config = enabled_fragment_provider_config(bad_key);
            let error =
                cell_retention_settings(&config).expect_err(&format!("{bad_key} must be refused"));
            assert!(
                error.to_string().contains(expected_field),
                "{bad_key} must be refused by name ({expected_field}), got {error}"
            );
        }
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

        let inventory = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), false)
            .expect("valid inventory");
        assert_eq!(
            inventory,
            FragmentProcessPoolInventory {
                immutable_pool_max: 1,
                mutable_pool_max: 2,
                lock_pool_max: 3,
                domain_pool_max: 4,
                dispatch_pool_max: 5,
                relay_pool_max: 0,
            }
        );

        // The relay flag decides presence, not size. With `[outbox_relay]` on,
        // the same three store configurations must reserve CR-032's whole pool
        // and nothing else about the inventory may move.
        let with_relay = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), true)
            .expect("valid inventory");
        assert_eq!(
            with_relay,
            FragmentProcessPoolInventory {
                relay_pool_max: crate::event_relay::RELAY_POOL_MAX,
                ..inventory
            }
        );
    }

    /// The escape this closes: a cell with NO fragment provider still opens the
    /// four store and domain pools, and CR-032's relay pool when the relay is
    /// on. It used to get no inventory at all, so nothing evaluated the
    /// ceiling for it. Now it gets one whose dispatch component is zero.
    #[test]
    fn a_provider_disabled_cell_still_declares_an_inventory_and_is_held_to_the_ceiling() {
        let immutable: toml::Value = toml::from_str(
            r#"
url = "postgresql://immutable@db.example/cell"
pool_max = 5
"#,
        )
        .expect("immutable config");
        let mutable: toml::Value = toml::from_str(
            r#"
url = "postgresql://mutable@db.example/cell"
pool_max = 5
domain_pool_max = 4
"#,
        )
        .expect("mutable config");
        let lock: toml::Value = toml::from_str(
            r#"
url = "postgresql://lock@db.example/cell"
pool_max = 5
"#,
        )
        .expect("lock config");

        // Relay off: no dispatch pool, no relay pool, 19 connections. Inside
        // the ceiling, and it validates.
        let relay_off = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), false)
            .expect("valid inventory");
        assert_eq!(relay_off.dispatch_pool_max, 0);
        assert_eq!(relay_off.relay_pool_max, 0);
        let validated = relay_off.validate().expect("19 is inside the ceiling");
        assert!(
            !validated.budget().opens_dispatch_pool(),
            "a provider-disabled cell must not look like one that opens a dispatch pool"
        );
        assert_eq!(validated.budget().connections_per_replica(), 19);

        // Relay on: the same cell is 24 and must now refuse, which is exactly
        // the staging shape and exactly what used to pass unevaluated.
        let relay_on = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), true)
            .expect("valid inventory");
        assert_eq!(relay_on.relay_pool_max, crate::event_relay::RELAY_POOL_MAX);
        assert!(
            relay_on.validate().is_err(),
            "24 connections must be refused on a provider-disabled cell too"
        );

        // A lock store that is not in Postgres mode opens no lock pool, so it
        // is declared as zero rather than skipping the ceiling. Without this
        // the same cell escaped at 10 + 10 + 4 + 5 = 29 against a limit of 20,
        // which is the escape this closes wearing a different hat.
        let no_lock_store = fragment_process_pool_inventory(&immutable, &mutable, None, true)
            .expect("valid inventory");
        assert_eq!(no_lock_store.lock_pool_max, 0);
        assert_eq!(
            no_lock_store
                .validate()
                .expect("5 + 5 + 4 + 5 is inside the ceiling")
                .budget()
                .connections_per_replica(),
            19
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

    // WP-114 CD-7 / WP-122 L5: the `[write_behind]` block.
    //
    // Every case below is executed on both platforms except the two that name a
    // platform in their own title. That is why `enabled_write_behind_settings`
    // runs its content and coupling checks *before* D13's Unix gate: with the
    // gate first, none of this would ever run on the rig this fork is written
    // on.

    /// An absolute path on the host running the test.
    ///
    /// The `cfg!(windows)` fork is load-bearing, not cosmetic, and it is the
    /// same trap that made all seven of `lore-fragment-provider`'s drain cases
    /// fail on Linux while passing here: a `C:\` literal is not `is_absolute()`
    /// on Linux, and a `/var/...` literal is not `is_absolute()` on Windows, so
    /// a single literal makes the valid fixture invalid on one of the two
    /// platforms — and production is the Linux one.
    fn staging_root() -> &'static str {
        if cfg!(windows) {
            "C:/lore/staging"
        } else {
            "/var/lib/loreserver/staging"
        }
    }

    /// The object-dispatch spool root, on the same platform fork and for the
    /// same reason as [`staging_root`].
    ///
    /// A sibling of the staging root rather than a child of it, because D15's
    /// whole point is that these are two trees. A fixture that nested them
    /// would be refused by the separateness check and every case built on it
    /// would fail for the wrong reason.
    fn spool_root() -> &'static str {
        if cfg!(windows) {
            "C:/lore/spool"
        } else {
            "/var/lib/loreserver/spool"
        }
    }

    /// A `[write_behind]` block with every required key present and coherent.
    fn valid_write_behind_block() -> String {
        format!(
            r#"
[write_behind]
enabled = true
root = "{}"
spool_root = "{}"
low_bytes = 1000
high_bytes = 2000
hard_bytes = 3000
low_count = 10
high_count = 20
hard_count = 30
min_free_bytes = 4096
drain_stale_after_millis = 30000
sample_interval_millis = 5000
"#,
            staging_root(),
            spool_root()
        )
    }

    /// The raw block, parsed out of a config that also enables a provider, so
    /// the coupling check has something to find.
    fn parsed_config_with(write_behind: &str) -> PostgresStoreConfig {
        let text = format!(
            r#"
url = "postgres://localhost/lore"
[object_store]
bucket = "fragments"
[fragment_provider]
enabled = true
{write_behind}
"#
        );
        match toml::from_str::<toml::Value>(&text).and_then(toml::Value::try_into) {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture config must deserialize: {error}"),
        }
    }

    fn raw_write_behind(write_behind: &str) -> WriteBehindConfig {
        match parsed_config_with(write_behind).write_behind {
            Some(raw) => raw,
            None => panic!("fixture must carry a write_behind block"),
        }
    }

    /// The content half, end to end: a complete block becomes exactly the
    /// settings the staging tier takes, with no value invented or rounded.
    #[test]
    fn a_complete_write_behind_block_converts_to_the_stages_own_settings() {
        let raw = raw_write_behind(&valid_write_behind_block());
        let composition = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
            Ok(composition) => composition,
            Err(error) => panic!("a complete block must validate: {error}"),
        };
        let settings = composition.settings;

        assert_eq!(settings.root, PathBuf::from(staging_root()));
        // D15's two roots arrive as two distinct values from the one block. The
        // inequality is asserted as well as each value, because the failure this
        // guards is not a wrong path but the SAME path arriving twice.
        assert_eq!(
            composition.shared_spool_root,
            PathBuf::from(spool_root()),
            "the spool root must be the spool_root key, not the staging root",
        );
        assert_ne!(composition.shared_spool_root, settings.root);
        assert_eq!(settings.watermarks.low_bytes, 1000);
        assert_eq!(settings.watermarks.high_bytes, 2000);
        assert_eq!(settings.watermarks.hard_bytes, 3000);
        assert_eq!(settings.watermarks.low_count, 10);
        assert_eq!(settings.watermarks.high_count, 20);
        assert_eq!(settings.watermarks.hard_count, 30);
        assert_eq!(settings.watermarks.min_free_bytes, 4096);
        assert_eq!(settings.drain_stale_after, Duration::from_millis(30_000));
        assert_eq!(settings.sample_interval, Duration::from_millis(5_000));
    }

    /// Absence and `enabled = false` are the two inert cases, and neither is an
    /// error: they leave every PUT on the synchronous object-store path.
    #[test]
    fn an_absent_or_disabled_write_behind_block_opens_no_staging_tier() {
        let absent = parsed_config_with("");
        assert!(matches!(
            enabled_write_behind_settings(PLUGIN_NAME, &absent),
            Ok(None)
        ));

        let disabled = parsed_config_with("[write_behind]\nenabled = false\n");
        assert!(matches!(
            enabled_write_behind_settings(PLUGIN_NAME, &disabled),
            Ok(None)
        ));

        // And the same two through the real boot door, for all three factories.
        for extra in ["", "[write_behind]\nenabled = false\n"] {
            let config = immutable_config(extra);
            assert!(parse_config(PLUGIN_NAME, &config).is_ok());
        }
    }

    /// There are no defaults, deliberately, so each omitted key must be refused
    /// **by name**. A refusal that does not name the key sends an operator
    /// looking through a block of twelve of them.
    #[test]
    fn every_omitted_write_behind_key_is_refused_by_its_own_name() {
        const REQUIRED: [&str; 11] = [
            "root",
            "spool_root",
            "low_bytes",
            "high_bytes",
            "hard_bytes",
            "low_count",
            "high_count",
            "hard_count",
            "min_free_bytes",
            "drain_stale_after_millis",
            "sample_interval_millis",
        ];
        let complete = valid_write_behind_block();
        for key in REQUIRED {
            let without = complete
                .lines()
                .filter(|line| !line.starts_with(&format!("{key} =")))
                .collect::<Vec<_>>()
                .join("\n");
            assert_ne!(
                without, complete,
                "the fixture must actually contain {key}, or this case removes nothing"
            );
            let raw = raw_write_behind(&without);
            let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
                Ok(_) => panic!("a block missing {key} must be refused"),
                Err(error) => error.to_string(),
            };
            let named = if key == "root" { "root" } else { key };
            assert!(
                error.contains(named),
                "the refusal for a missing {key} must name it; got {error}"
            );
        }
    }

    /// An unknown key is a typo, and a typo in a block with no defaults would
    /// otherwise be reported as the *adjacent* key being missing.
    #[test]
    fn an_unknown_write_behind_key_is_refused_rather_than_ignored() {
        let text = format!(
            r#"
url = "postgres://localhost/lore"
{}
staging_root = "/var/lib/loreserver/staging"
"#,
            valid_write_behind_block()
        );
        let value: toml::Value = match toml::from_str(&text) {
            Ok(value) => value,
            Err(error) => panic!("fixture must parse as TOML: {error}"),
        };
        let error = match value.try_into::<PostgresStoreConfig>() {
            Ok(_) => panic!("an unknown write_behind key must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("staging_root"),
            "the refusal must name the unknown key; got {error}"
        );
    }

    /// The values that are individually present and jointly impossible.
    ///
    /// Each of these produces no error anywhere in the staging tier itself. A
    /// mis-ordered pair yields a hysteresis latch that can never clear, which
    /// reads as a cell permanently in direct fallback with nothing to explain
    /// it; a zero ceiling refuses every PUT the moment occupancy is observed at
    /// all, because the watermark comparison is `>=`.
    #[test]
    fn incoherent_write_behind_thresholds_are_refused_at_configuration_time() {
        // Each case is a set of substitutions, because a zero ceiling on its
        // own also breaks the ordering rule and would be refused by the wrong
        // check — which would leave the positivity check itself unproved.
        const CASES: [(&[(&str, &str)], &str); 7] = [
            (
                &[("low_bytes = 1000", "low_bytes = 2500")],
                "low_bytes <= high_bytes",
            ),
            (
                &[("high_bytes = 2000", "high_bytes = 4000")],
                "high_bytes <= hard_bytes",
            ),
            (
                &[("low_count = 10", "low_count = 25")],
                "low_count <= high_count",
            ),
            (
                &[("high_count = 20", "high_count = 40")],
                "high_count <= hard_count",
            ),
            (
                &[
                    ("low_bytes = 1000", "low_bytes = 0"),
                    ("high_bytes = 2000", "high_bytes = 0"),
                    ("hard_bytes = 3000", "hard_bytes = 0"),
                ],
                "positive",
            ),
            (
                &[
                    ("low_count = 10", "low_count = 0"),
                    ("high_count = 20", "high_count = 0"),
                    ("hard_count = 30", "hard_count = 0"),
                ],
                "positive",
            ),
            (
                &[("min_free_bytes = 4096", "min_free_bytes = 0")],
                "positive",
            ),
        ];
        let complete = valid_write_behind_block();
        for (substitutions, expected) in CASES {
            let mut mutated = complete.clone();
            for (from, to) in substitutions {
                let next = mutated.replace(from, to);
                assert_ne!(
                    next, mutated,
                    "the fixture must contain `{from}`, or this case mutates nothing"
                );
                mutated = next;
            }
            let raw = raw_write_behind(&mutated);
            let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
                Ok(_) => panic!("{substitutions:?} must be refused"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(expected),
                "{substitutions:?} must be refused naming {expected}; got {error}"
            );
        }
    }

    /// A relative root resolves against the process working directory, which is
    /// an operator-invisible input: the same configuration would stage into
    /// different filesystems depending on how the unit was launched.
    #[test]
    fn a_relative_or_empty_staging_root_is_refused() {
        let complete = valid_write_behind_block();
        // Both keys, because `spool_root` is a second absolute path with the
        // same working-directory hazard and nothing about the first key's
        // coverage carries over to it.
        for (key, configured) in [("root", staging_root()), ("spool_root", spool_root())] {
            for (root, expected) in [
                ("staging", "absolute"),
                ("", "non-empty"),
                ("   ", "non-empty"),
            ] {
                let mutated = complete.replace(
                    &format!(r#"{key} = "{configured}""#),
                    &format!(r#"{key} = "{root}""#),
                );
                assert_ne!(
                    mutated, complete,
                    "the fixture must contain `{key} = \"{configured}\"`"
                );
                let raw = raw_write_behind(&mutated);
                let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
                    Ok(_) => panic!("{key} `{root}` must be refused"),
                    Err(error) => error.to_string(),
                };
                assert!(
                    error.contains(expected) && error.contains(key),
                    "{key} `{root}` must be refused naming {expected} and {key}; got {error}"
                );
            }
        }
    }

    /// Owner ruling D15: the staging root and the spool root are two separate
    /// trees, and a configuration that merges them is refused rather than
    /// honoured.
    ///
    /// This is a correctness refusal, not tidiness. Contract C2's orphan
    /// reclaimer enumerates the staging tree and reclaims what the coordinator
    /// confirms absent from the epoch table — and a spool file legitimately has
    /// no epoch row. So a spool root at, or under, the staging root puts
    /// in-flight upload bytes inside the reclaimer's delete set. The reverse
    /// nesting is refused too, because it puts a foreign writer inside the tree
    /// `ConfinedRoot` fsyncs on every staged write.
    ///
    /// All three shapes are covered — equal, spool under staging, staging under
    /// spool — because an equality-only check passes the two that matter.
    #[test]
    fn a_spool_root_sharing_the_staging_tree_is_refused() {
        let complete = valid_write_behind_block();
        let nested_spool = format!("{}/spool", staging_root());
        let parent_spool = match PathBuf::from(staging_root()).parent() {
            Some(parent) => parent.to_string_lossy().replace('\\', "/"),
            None => panic!("the staging-root fixture must have a parent"),
        };
        for (label, spool) in [
            ("equal", staging_root().to_owned()),
            ("spool under staging", nested_spool),
            ("staging under spool", parent_spool),
        ] {
            let mutated = complete.replace(
                &format!(r#"spool_root = "{}""#, spool_root()),
                &format!(r#"spool_root = "{spool}""#),
            );
            assert_ne!(
                mutated, complete,
                "the {label} case must mutate the fixture"
            );
            let raw = raw_write_behind(&mutated);
            let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
                Ok(_) => panic!("a {label} spool root must be refused"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("separate trees"),
                "the {label} case must be refused naming the separateness rule; got {error}"
            );
        }
    }

    /// The lower bound is not tidiness. The sampler builds a
    /// `tokio::time::interval` from `sample_interval_millis`, and that
    /// constructor **panics** on a zero period, so without this refusal a
    /// zero would be a panicking background task rather than a config error.
    /// The upper bound catches the unit mistake: a milliseconds field filled in
    /// as if it were seconds.
    #[test]
    fn out_of_range_write_behind_intervals_are_refused() {
        let complete = valid_write_behind_block();
        const CASES: [(&str, &str); 4] = [
            (
                "sample_interval_millis = 5000",
                "sample_interval_millis = 0",
            ),
            (
                "sample_interval_millis = 5000",
                "sample_interval_millis = 3600001",
            ),
            (
                "drain_stale_after_millis = 30000",
                "drain_stale_after_millis = 0",
            ),
            (
                "drain_stale_after_millis = 30000",
                "drain_stale_after_millis = 3600001",
            ),
        ];
        for (from, to) in CASES {
            let mutated = complete.replace(from, to);
            assert_ne!(mutated, complete, "the fixture must contain `{from}`");
            let raw = raw_write_behind(&mutated);
            let field = to.split(' ').next().unwrap_or_default();
            let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
                Ok(_) => panic!("`{to}` must be refused"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(field) && error.contains("between 1 and 3600000"),
                "`{to}` must be refused naming {field} and its bounds; got {error}"
            );
        }
    }

    /// The inert-wiring refusal. The staged route is reached only from the
    /// coordinated PUT path, so a legacy cell would prove a staging root, run
    /// its sampler, publish a healthy admission picture, and never stage a
    /// byte.
    #[test]
    fn an_enabled_write_behind_without_a_governed_route_is_refused() {
        for provider in ["", "[fragment_provider]\nenabled = false\n"] {
            let text = format!(
                r#"
url = "postgres://localhost/lore"
[object_store]
bucket = "fragments"
{provider}
{}
"#,
                valid_write_behind_block()
            );
            let parsed: PostgresStoreConfig =
                match toml::from_str::<toml::Value>(&text).and_then(toml::Value::try_into) {
                    Ok(parsed) => parsed,
                    Err(error) => panic!("fixture config must deserialize: {error}"),
                };
            let error = match enabled_write_behind_settings(PLUGIN_NAME, &parsed) {
                Ok(_) => panic!("an enabled tier with no governed route must be refused"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("requires an enabled fragment_provider"),
                "the refusal must name the coupling; got {error}"
            );
        }
    }

    /// D13's boot-time half, on a host that cannot stage.
    ///
    /// The compile-time half is `ConfinedRoot`'s `cfg(not(unix))` module, which
    /// refuses every operation. This is the other half, and it is the one that
    /// matters to an operator: without it a cell configured for staging boots,
    /// reports healthy, and learns the truth one failed PUT at a time.
    #[cfg(not(unix))]
    #[test]
    fn an_otherwise_valid_write_behind_block_is_refused_at_boot_off_unix() {
        let parsed = parsed_config_with(&valid_write_behind_block());
        let error = match enabled_write_behind_settings(PLUGIN_NAME, &parsed) {
            Ok(_) => panic!("staging must be refused off Unix"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("requires a Unix host"),
            "the refusal must name the platform, not a field; got {error}"
        );
    }

    /// The same block, on the platform that can stage, must be accepted — so
    /// the case above is proved to be refusing for its stated reason rather
    /// than tripping over a fixture that was never valid anywhere.
    #[cfg(unix)]
    #[test]
    fn the_same_write_behind_block_is_accepted_on_unix() {
        let parsed = parsed_config_with(&valid_write_behind_block());
        let composition = match enabled_write_behind_settings(PLUGIN_NAME, &parsed) {
            Ok(Some(composition)) => composition,
            Ok(None) => panic!("an enabled block must produce settings"),
            Err(error) => panic!("an enabled block must be accepted on Unix: {error}"),
        };
        assert_eq!(composition.settings.root, PathBuf::from(staging_root()));
        assert_eq!(composition.shared_spool_root, PathBuf::from(spool_root()));
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
