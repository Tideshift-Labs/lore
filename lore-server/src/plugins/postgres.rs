// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
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

use std::sync::Arc;

use lore_base::error::PluginConfigError;
use lore_base::error::PluginInitError;
use lore_base::runtime::runtime;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
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
    /// `pool_max`. The coordinator is a **fourth** pool on every Postgres cell,
    /// added whether or not domain enforcement is on, so inheriting a
    /// `pool_max` of 10 would raise a cell's steady-state connection count by a
    /// third to serve a subsystem that is idle until cutover. The two things it
    /// actually does before then - bootstrap DDL and a singleton state read -
    /// need one connection, and the backfill walks one repository at a time.
    /// Raise it when a cell enables enforcement.
    #[serde(default = "default_domain_pool_max")]
    pub domain_pool_max: u32,
    /// S3-compatible object storage for fragment bytes and authoritative
    /// representation metadata. Required by the immutable-store factory;
    /// unused (and typically absent) for the mutable/lock stores, which keep
    /// everything in Postgres.
    #[serde(default)]
    pub object_store: Option<ObjectStoreConfig>,
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

fn default_pool_max() -> u32 {
    10
}

fn default_domain_pool_max() -> u32 {
    4
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

fn parse_config(name: &str, config: &toml::Value) -> Result<PostgresStoreConfig, PluginError> {
    config.clone().try_into().map_err(|e| {
        PluginError::from(PluginConfigError {
            plugin_name: name.to_string(),
            message: format!("Failed to deserialize Postgres store config: {e}"),
        })
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

/// Build the concrete Postgres immutable store from the plugin configuration.
///
/// Both normal server startup and offline maintenance use this path so config
/// fallback, TLS, object-store settings, and the standard AWS credential chain
/// cannot drift between them.
pub(crate) async fn connect_immutable_store(
    config: &toml::Value,
) -> Result<PostgresImmutableStore, PluginError> {
    let plugin_name = PLUGIN_NAME;
    let cfg = parse_config(plugin_name, config)?;
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

    PostgresImmutableStore::connect(&cfg.url, cfg.pool_max, &tls, object)
        .await
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to create Postgres immutable store: {e}"),
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
            runtime().block_on(Box::pin(connect_immutable_store(config)))
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

    fn create(
        &self,
        config: &toml::Value,
        _immutable_store: Arc<dyn ImmutableStore>,
    ) -> Result<Arc<dyn MutableStore>, PluginError> {
        // The Postgres mutable store is standalone (branch-tip CAS needs no
        // fragment storage), so the immutable-store dependency is unused.
        let plugin_name = self.name();
        let cfg = parse_config(plugin_name, config)?;
        let tls = build_tls(plugin_name, &cfg)?;

        // Plugin construction is a synchronous trait method. It runs once at
        // startup, one plugin at a time, so at most one core is handed off.
        #[allow(clippy::disallowed_methods)]
        let store = tokio::task::block_in_place(|| {
            runtime().block_on(PostgresMutableStore::connect(&cfg.url, cfg.pool_max, &tls))
        })
        .map_err(|e| {
            PluginError::from(PluginInitError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to create Postgres mutable store: {e}"),
            })
        })?;

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
    use super::*;

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
}
