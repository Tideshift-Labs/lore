// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! The fourth, separately credentialed dispatch-runtime connection pool (WP-114 CD-3).
//!
//! CR-033 D1 made the cell's own PostgreSQL database the dispatch authority. Every retained
//! mutation asserts `session_user = 'object_dispatch_retention_runtime'` and grants `EXECUTE` only
//! to that role, and 0020's enrollment asserts the maintenance role, so `lore-postgres`'s existing
//! CR-007 store pools cannot carry these calls: they connect as the store identity. This module
//! owns the extra pool, its credential identity check, and its bounded-execution settings.
//!
//! The pool is source-dark. Constructing it opens connections to whatever database the caller
//! names; it installs no schema, publishes no configuration, and is not wired into loreserver
//! composition.

use std::fmt;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio_postgres::Client;
use tokio_postgres::config::Host;
use tokio_postgres::config::SslMode;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;

/// The PostgreSQL role every 0013/0015/0017 mutation and 0020 registration asserts.
pub const DISPATCH_RUNTIME_ROLE: &str = "object_dispatch_retention_runtime";

/// The PostgreSQL role 0020's participant enrollment asserts.
pub const DISPATCH_MAINTENANCE_ROLE: &str = "object_dispatch_retention_maintenance";

/// The connection-budget statement this pool is sized against, stated rather than implied.
///
/// CR-033 D1 makes the cell database the dispatch authority, so a loreserver replica in a cell
/// opens this fourth pool beside `lore-postgres`'s three CR-007 store pools. All four target the
/// same cell database and none of them coordinate on connections, so a replica's ceiling is the
/// **sum** of their `pool_max` values, not the largest of them. At staging's `pool_max = 5` that is
/// `(3 store pools + 1 dispatch pool) * 5 = 20` connections per replica, before the control plane's
/// own pools on the same instance are counted.
///
/// This is `lorehub/docs/learnings/do-managed-pg-connection-budget.md`'s finding: a managed
/// instance sized for the app pools alone rather than the full consumer set was exhausted at
/// `max_connections = 25`, and the exhaustion surfaced as SQLSTATE `53300` in three
/// unrelated-looking failures rather than as an obvious pool error.
pub const DISPATCH_CONNECTION_BUDGET_STATEMENT: &str = "\
Per loreserver replica in a cell: 3 lore-postgres CR-007 store pools + 1 lore-object-dispatch \
dispatch-runtime pool, all against the same cell database, none coordinating on connections. \
At staging's pool_max = 5 that is (3 + 1) * 5 = 20 PostgreSQL connections per replica. The managed \
instance must be sized for that sum across every replica plus every other consumer of the same \
instance, per lorehub/docs/learnings/do-managed-pg-connection-budget.md.";

/// The per-replica pool arithmetic behind [`DISPATCH_CONNECTION_BUDGET_STATEMENT`].
///
/// A [`DispatchPoolConfig`] is refused when its `pool_max` exceeds the budget it declares, so one
/// pool cannot quietly grow past what its own configuration says.
///
/// **What this does not enforce, and where that lands.** The budget is supplied by the caller, and
/// a pool can only see itself: nothing here counts how many dispatch pools a process actually
/// opens, or checks that `store_pools` matches what `lore-postgres` really built. Two pools each
/// declaring `dispatch_pools: 1` are each individually valid and together exceed the stated
/// twenty. Making the sum true is a composition-time obligation that lands with the loreserver
/// wiring in CD-6, not something this crate can check from inside one pool, and it is recorded as
/// a named residual in WP-114 CD-3 rather than left implied.
///
/// [`STAGING_DISPATCH_CONNECTION_BUDGET`] describes the request path: three store pools and the
/// **one** runtime dispatch pool a replica keeps open. A maintenance pool is not part of that
/// steady state - 0020's enrollment is an out-of-band operator action, like the schema installer -
/// so a process that opens one must declare its own budget rather than reusing this constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchConnectionBudget {
    /// `lore-postgres`'s CR-007 store pools on the same cell database.
    pub store_pools: u32,
    /// Dispatch-runtime pools this crate opens. One per replica.
    pub dispatch_pools: u32,
    /// The `pool_max` each of those pools is configured with.
    pub pool_max: u32,
}

/// Staging's shape: three store pools, one dispatch pool, `pool_max = 5`, so 20 per replica.
pub const STAGING_DISPATCH_CONNECTION_BUDGET: DispatchConnectionBudget = DispatchConnectionBudget {
    store_pools: 3,
    dispatch_pools: 1,
    pool_max: 5,
};

impl DispatchConnectionBudget {
    /// Total PostgreSQL connections one loreserver replica may hold open against the cell database.
    pub const fn connections_per_replica(self) -> Option<u32> {
        match self.store_pools.checked_add(self.dispatch_pools) {
            Some(pools) => pools.checked_mul(self.pool_max),
            None => None,
        }
    }

    fn validate(self) -> Result<u32, DispatchPoolError> {
        if self.dispatch_pools == 0 || self.pool_max == 0 {
            return Err(DispatchPoolError::InvalidConfiguration(
                "connection budget must allow at least one dispatch pool of at least one \
                 connection",
            ));
        }
        self.connections_per_replica()
            .ok_or(DispatchPoolError::InvalidConfiguration(
                "connection budget overflows a per-replica connection count",
            ))
    }
}

/// How the pool negotiates TLS to the cell database.
///
/// The mandatory client certificate and pinned-CA contract in `retention_client` was written for an
/// external authority database and does not survive CR-033 D1; the cell authority is the cell's own
/// database. What does survive is fail-closed posture. The two modes each pin the URL's `sslmode`
/// exactly, so `prefer` - which negotiates TLS and silently falls back to plaintext when the
/// handshake fails - is never reachable, and a pinned CA is never configured beside a URL that
/// would not use it.
///
/// Server verification is never skipped. `tokio-postgres` delegates verification to the connector
/// and rustls always checks the trust roots, so [`DispatchTlsMode::PinnedRootCa`] behaves like
/// libpq's `verify-ca` rather than libpq's lax `require`.
#[derive(Clone, Default)]
pub enum DispatchTlsMode {
    /// A cell-local database reached without TLS. Requires `sslmode=disable` in the URL.
    #[default]
    Disabled,
    /// Verify the server against exactly this PEM bundle. Requires `sslmode=require` in the URL.
    PinnedRootCa(String),
}

impl fmt::Debug for DispatchTlsMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::PinnedRootCa(_) => formatter.write_str("PinnedRootCa([REDACTED])"),
        }
    }
}

/// Everything the dispatch-runtime pool needs, and nothing it may disclose.
#[derive(Clone)]
pub struct DispatchPoolConfig {
    /// The cell database URL, including this pool's own credential.
    pub postgres_url: String,
    /// Which authority identity this pool connects as.
    pub role: DispatchPoolRole,
    /// Concurrent connections this pool may hold. Bounded by `budget.pool_max`.
    pub pool_max: u32,
    pub connect_timeout: Duration,
    /// Time a caller waits for a pool slot before failing closed.
    pub acquire_timeout: Duration,
    /// `SET LOCAL statement_timeout` for every transaction the client opens.
    pub statement_timeout: Duration,
    /// `SET LOCAL lock_timeout` for every transaction the client opens.
    pub lock_timeout: Duration,
    pub tls: DispatchTlsMode,
    /// The per-replica budget this pool's `pool_max` is checked against.
    pub budget: DispatchConnectionBudget,
}

impl fmt::Debug for DispatchPoolConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchPoolConfig")
            .field("postgres_url", &"[REDACTED]")
            .field("role", &self.role)
            .field("pool_max", &self.pool_max)
            .field("connect_timeout", &self.connect_timeout)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("lock_timeout", &self.lock_timeout)
            .field("tls", &self.tls)
            .field("budget", &self.budget)
            .finish()
    }
}

/// Which authority identity a pool connects as. The two are never mixed on one connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchPoolRole {
    /// 0013, 0015, 0017 mutations, 0020 registration, and 0019's readback.
    Runtime,
    /// 0020 participant enrollment only.
    Maintenance,
}

impl DispatchPoolRole {
    /// The exact `session_user` the cell procedures assert for this identity.
    pub const fn role_name(self) -> &'static str {
        match self {
            Self::Runtime => DISPATCH_RUNTIME_ROLE,
            Self::Maintenance => DISPATCH_MAINTENANCE_ROLE,
        }
    }
}

/// Why the pool refused a configuration or could not hand out a session.
///
/// No variant carries a URL, a credential, a PEM, a PostgreSQL diagnostic, or a parameter value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DispatchPoolError {
    #[error("invalid dispatch pool configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid dispatch pool TLS material: {0}")]
    InvalidTlsMaterial(&'static str),
    #[error("dispatch pool connection timed out")]
    ConnectTimeout,
    #[error("dispatch pool has no free connection slot")]
    PoolExhausted,
    #[error("dispatch pool could not open a cell database connection")]
    ConnectFailed,
}

/// One pooled PostgreSQL connection.
struct DispatchSession {
    client: Client,
    _connection_task: AbortOnDropHandle<()>,
}

/// The fourth, separately credentialed pool.
///
/// Connections are opened on demand up to `pool_max` and returned to the idle set when a lease is
/// dropped. A lease the caller marks poisoned is closed rather than reused, which is what the
/// bounded-execution envelope's reconnect-after-ambiguity step needs.
pub struct DispatchRuntimePool {
    config: DispatchPoolConfig,
    permits: Semaphore,
    idle: Mutex<Vec<DispatchSession>>,
    statement_timeout_ms: u64,
    lock_timeout_ms: u64,
    operation_timeout: Duration,
    connections_per_replica: u32,
}

impl fmt::Debug for DispatchRuntimePool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchRuntimePool")
            .field("config", &self.config)
            .field("statement_timeout_ms", &self.statement_timeout_ms)
            .field("lock_timeout_ms", &self.lock_timeout_ms)
            .field("operation_timeout", &self.operation_timeout)
            .field("connections_per_replica", &self.connections_per_replica)
            .finish_non_exhaustive()
    }
}

impl DispatchRuntimePool {
    /// Validate the configuration and build an empty pool. No connection is opened here.
    pub fn new(config: DispatchPoolConfig) -> Result<Self, DispatchPoolError> {
        let connections_per_replica = config.budget.validate()?;
        if config.pool_max == 0 {
            return Err(DispatchPoolError::InvalidConfiguration(
                "dispatch pool_max must be positive",
            ));
        }
        if config.pool_max > config.budget.pool_max {
            return Err(DispatchPoolError::InvalidConfiguration(
                "dispatch pool_max exceeds the declared per-replica connection budget",
            ));
        }
        let statement_timeout_ms = whole_millis(
            config.statement_timeout,
            "statement timeout must be a positive whole-millisecond value",
        )?;
        let lock_timeout_ms = whole_millis(
            config.lock_timeout,
            "lock timeout must be a positive whole-millisecond value",
        )?;
        positive_duration(config.connect_timeout, "connect timeout must be positive")?;
        positive_duration(config.acquire_timeout, "acquire timeout must be positive")?;
        let operation_timeout = config
            .statement_timeout
            .checked_add(config.lock_timeout)
            .ok_or(DispatchPoolError::InvalidConfiguration(
                "combined operation timeout is too large",
            ))?;
        // Reject the connection material once at construction so a caller cannot discover an
        // unusable URL or an unusable CA bundle only on the first authority call.
        let _ = connection_material(&config)?;
        let permits = usize::try_from(config.pool_max).map_err(|_| {
            DispatchPoolError::InvalidConfiguration("dispatch pool_max is too large")
        })?;
        Ok(Self {
            config,
            permits: Semaphore::new(permits),
            idle: Mutex::new(Vec::new()),
            statement_timeout_ms,
            lock_timeout_ms,
            operation_timeout,
            connections_per_replica,
        })
    }

    /// The identity this pool connects as.
    pub const fn role(&self) -> DispatchPoolRole {
        self.config.role
    }

    /// `statement_timeout + lock_timeout`; the wall-clock bound on one authority call.
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Connections one replica may hold across all four pools, per the declared budget.
    pub const fn connections_per_replica(&self) -> u32 {
        self.connections_per_replica
    }

    /// The `SET LOCAL` statement every transaction opens with.
    pub(crate) fn bounded_execution_preamble(&self) -> String {
        format!(
            "SET LOCAL statement_timeout = '{}ms'; SET LOCAL lock_timeout = '{}ms';",
            self.statement_timeout_ms, self.lock_timeout_ms
        )
    }

    /// Take one connection out of the pool, opening a new one if the pool is below `pool_max`.
    pub(crate) async fn acquire(&self) -> Result<DispatchLease<'_>, DispatchPoolError> {
        let permit = tokio::time::timeout(self.config.acquire_timeout, self.permits.acquire())
            .await
            .map_err(|_| DispatchPoolError::PoolExhausted)?
            .map_err(|_| DispatchPoolError::PoolExhausted)?;
        loop {
            let reused = self.idle.lock().await.pop();
            match reused {
                Some(session) if !session.client.is_closed() => {
                    return Ok(DispatchLease {
                        pool: self,
                        session: Some(session),
                        _permit: permit,
                    });
                }
                // A closed idle connection is dropped, not handed out. Keep looking before paying
                // for a new one.
                Some(_) => continue,
                None => break,
            }
        }
        let session = self.connect().await?;
        Ok(DispatchLease {
            pool: self,
            session: Some(session),
            _permit: permit,
        })
    }

    async fn connect(&self) -> Result<DispatchSession, DispatchPoolError> {
        let (postgres, tls) = connection_material(&self.config)?;
        let (client, connection) =
            tokio::time::timeout(self.config.connect_timeout, postgres.connect(tls))
                .await
                .map_err(|_| DispatchPoolError::ConnectTimeout)?
                .map_err(|_| DispatchPoolError::ConnectFailed)?;
        let connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "object-store-dispatch-postgres",
            async move {
                if connection.await.is_err() {
                    // No PostgreSQL diagnostic reaches the log line.
                    tracing::error!("object-store dispatch PostgreSQL connection ended");
                }
            }
        ));
        Ok(DispatchSession {
            client,
            _connection_task: connection_task,
        })
    }

    async fn release(&self, session: DispatchSession) {
        if session.client.is_closed() {
            return;
        }
        let mut idle = self.idle.lock().await;
        if u32::try_from(idle.len()).is_ok_and(|held| held < self.config.pool_max) {
            idle.push(session);
        }
    }
}

/// A borrowed pool connection. Dropping it returns the connection; [`DispatchLease::poison`]
/// closes it instead.
pub(crate) struct DispatchLease<'a> {
    pool: &'a DispatchRuntimePool,
    session: Option<DispatchSession>,
    _permit: tokio::sync::SemaphorePermit<'a>,
}

impl DispatchLease<'_> {
    pub(crate) fn client(&mut self) -> Result<&mut Client, DispatchPoolError> {
        match self.session.as_mut() {
            Some(session) => Ok(&mut session.client),
            None => Err(DispatchPoolError::ConnectFailed),
        }
    }

    /// Return the connection to the pool now, before the caller sleeps between retry attempts.
    ///
    /// CR-033 D1's envelope requires the session to be released before a retry delay so a bounded
    /// pool is not held idle across the backoff.
    pub(crate) async fn release(mut self) {
        if let Some(session) = self.session.take() {
            self.pool.release(session).await;
        }
    }

    /// Drop the connection without returning it. Used when a transaction's outcome is unknown, so
    /// the next attempt runs on a connection whose server-side state is not in doubt.
    pub(crate) fn poison(mut self) {
        drop(self.session.take());
    }
}

impl Drop for DispatchLease<'_> {
    fn drop(&mut self) {
        // A lease dropped without an explicit release cannot await the idle mutex here, so the
        // connection is closed rather than silently leaked back into the pool at an unknown point.
        drop(self.session.take());
    }
}

fn connection_material(
    config: &DispatchPoolConfig,
) -> Result<(tokio_postgres::Config, MakeRustlsConnect), DispatchPoolError> {
    let postgres = config
        .postgres_url
        .parse::<tokio_postgres::Config>()
        .map_err(|_| DispatchPoolError::InvalidConfiguration("invalid PostgreSQL URL"))?;
    let [Host::Tcp(_)] = postgres.get_hosts() else {
        return Err(DispatchPoolError::InvalidConfiguration(
            "dispatch pool requires exactly one TCP host",
        ));
    };
    if postgres.get_dbname().is_none() {
        return Err(DispatchPoolError::InvalidConfiguration(
            "dispatch pool URL requires a database name",
        ));
    }
    // The procedures authorize on session_user. A pool that connects as anything else fails closed
    // in the database, so refuse it here where the reason is still legible.
    if postgres.get_user() != Some(config.role.role_name()) {
        return Err(DispatchPoolError::InvalidConfiguration(
            "dispatch pool URL user must be the exact authority role for this pool",
        ));
    }
    let mut roots = RootCertStore::empty();
    match &config.tls {
        DispatchTlsMode::Disabled => {
            if postgres.get_ssl_mode() != SslMode::Disable {
                return Err(DispatchPoolError::InvalidConfiguration(
                    "dispatch pool without TLS material requires sslmode=disable",
                ));
            }
        }
        DispatchTlsMode::PinnedRootCa(pem) => {
            if postgres.get_ssl_mode() != SslMode::Require {
                return Err(DispatchPoolError::InvalidConfiguration(
                    "dispatch pool with a pinned root CA requires sslmode=require",
                ));
            }
            let mut reader = Cursor::new(pem.as_bytes());
            let mut added = 0usize;
            for certificate in rustls_pemfile::certs(&mut reader) {
                let certificate = certificate
                    .map_err(|_| DispatchPoolError::InvalidTlsMaterial("invalid root CA PEM"))?;
                roots.add(certificate).map_err(|_| {
                    DispatchPoolError::InvalidTlsMaterial("unusable root CA certificate")
                })?;
                added = added.saturating_add(1);
            }
            if added == 0 {
                return Err(DispatchPoolError::InvalidTlsMaterial(
                    "pinned root CA bundle is empty",
                ));
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| DispatchPoolError::InvalidTlsMaterial("unsupported TLS protocol set"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok((postgres, MakeRustlsConnect::new(tls)))
}

fn positive_duration(value: Duration, message: &'static str) -> Result<(), DispatchPoolError> {
    if value.is_zero() {
        return Err(DispatchPoolError::InvalidConfiguration(message));
    }
    Ok(())
}

fn whole_millis(value: Duration, message: &'static str) -> Result<u64, DispatchPoolError> {
    if value.is_zero() || value.as_millis() == 0 || !value.subsec_nanos().is_multiple_of(1_000_000)
    {
        return Err(DispatchPoolError::InvalidConfiguration(message));
    }
    u64::try_from(value.as_millis())
        .map_err(|_| DispatchPoolError::InvalidConfiguration("timeout is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DispatchPoolConfig {
        DispatchPoolConfig {
            postgres_url: format!(
                "postgres://{DISPATCH_RUNTIME_ROLE}:secret@cell.invalid:5432/lorecell?sslmode=disable"
            ),
            role: DispatchPoolRole::Runtime,
            pool_max: 5,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_millis(2_000),
            lock_timeout: Duration::from_millis(1_000),
            tls: DispatchTlsMode::Disabled,
            budget: STAGING_DISPATCH_CONNECTION_BUDGET,
        }
    }

    #[test]
    fn staging_budget_is_twenty_connections_per_replica() {
        assert_eq!(
            STAGING_DISPATCH_CONNECTION_BUDGET.connections_per_replica(),
            Some(20)
        );
        assert_eq!(STAGING_DISPATCH_CONNECTION_BUDGET.store_pools, 3);
        assert_eq!(STAGING_DISPATCH_CONNECTION_BUDGET.dispatch_pools, 1);
        assert_eq!(STAGING_DISPATCH_CONNECTION_BUDGET.pool_max, 5);
    }

    #[test]
    fn pool_max_above_the_declared_budget_is_refused() {
        let mut value = config();
        value.pool_max = 6;
        assert_eq!(
            DispatchRuntimePool::new(value).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "dispatch pool_max exceeds the declared per-replica connection budget"
            ))
        );
    }

    #[test]
    fn a_url_naming_another_role_is_refused_for_both_identities() {
        let mut runtime = config();
        runtime.role = DispatchPoolRole::Maintenance;
        assert_eq!(
            DispatchRuntimePool::new(runtime).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "dispatch pool URL user must be the exact authority role for this pool"
            ))
        );
        let mut maintenance = config();
        maintenance.postgres_url = format!(
            "postgres://{DISPATCH_MAINTENANCE_ROLE}:secret@cell.invalid:5432/lorecell?sslmode=disable"
        );
        assert_eq!(
            DispatchRuntimePool::new(maintenance).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "dispatch pool URL user must be the exact authority role for this pool"
            ))
        );
    }

    #[test]
    fn a_valid_maintenance_configuration_is_accepted() {
        let mut value = config();
        value.role = DispatchPoolRole::Maintenance;
        value.postgres_url = format!(
            "postgres://{DISPATCH_MAINTENANCE_ROLE}:secret@cell.invalid:5432/lorecell?sslmode=disable"
        );
        let pool = DispatchRuntimePool::new(value).expect("maintenance pool");
        assert_eq!(pool.role(), DispatchPoolRole::Maintenance);
        assert_eq!(pool.connections_per_replica(), 20);
    }

    #[test]
    fn configuration_debug_discloses_no_url_or_tls_material() {
        let mut value = config();
        value.tls = DispatchTlsMode::PinnedRootCa("-----BEGIN CERTIFICATE-----".into());
        let rendered = format!("{value:?}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(!rendered.contains("cell.invalid"), "{rendered}");
        assert!(!rendered.contains("BEGIN CERTIFICATE"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[test]
    fn pool_debug_discloses_no_url() {
        let pool = DispatchRuntimePool::new(config()).expect("pool");
        let rendered = format!("{pool:?}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(!rendered.contains("cell.invalid"), "{rendered}");
    }

    #[test]
    fn every_timeout_is_refused_with_its_own_message_when_fractional_or_zero() {
        // All four, each asserted against its own message: a message attached to the wrong field
        // would otherwise pass, and the two-of-four version of this test could not see it.
        for (name, apply) in [
            (
                "statement timeout must be a positive whole-millisecond value",
                (|value: &mut DispatchPoolConfig| {
                    value.statement_timeout = Duration::from_micros(1_500)
                }) as fn(&mut DispatchPoolConfig),
            ),
            (
                "lock timeout must be a positive whole-millisecond value",
                |value: &mut DispatchPoolConfig| value.lock_timeout = Duration::from_micros(1_500),
            ),
            (
                "connect timeout must be positive",
                |value: &mut DispatchPoolConfig| {
                    value.connect_timeout = Duration::ZERO;
                },
            ),
            (
                "acquire timeout must be positive",
                |value: &mut DispatchPoolConfig| {
                    value.acquire_timeout = Duration::ZERO;
                },
            ),
        ] {
            let mut value = config();
            apply(&mut value);
            assert_eq!(
                DispatchRuntimePool::new(value).err(),
                Some(DispatchPoolError::InvalidConfiguration(name)),
                "{name}"
            );
        }
        // Zero is refused for the whole-millisecond timeouts too, by the same message.
        let mut zero_statement = config();
        zero_statement.statement_timeout = Duration::ZERO;
        assert_eq!(
            DispatchRuntimePool::new(zero_statement).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "statement timeout must be a positive whole-millisecond value"
            ))
        );
    }

    #[test]
    fn an_empty_pinned_ca_bundle_is_refused() {
        let mut value = config();
        value.postgres_url = value
            .postgres_url
            .replace("sslmode=disable", "sslmode=require");
        value.tls = DispatchTlsMode::PinnedRootCa(String::new());
        assert_eq!(
            DispatchRuntimePool::new(value).err(),
            Some(DispatchPoolError::InvalidTlsMaterial(
                "pinned root CA bundle is empty"
            ))
        );
    }

    #[test]
    fn the_tls_mode_and_the_urls_sslmode_must_agree_in_both_directions() {
        // A pinned CA beside a URL that will not use it, and a plaintext pool beside a URL that
        // would negotiate TLS, are both refused. `prefer` - which falls back to plaintext when the
        // handshake fails - is unreachable through either mode.
        let mut pinned_but_plaintext = config();
        pinned_but_plaintext.tls =
            DispatchTlsMode::PinnedRootCa("-----BEGIN CERTIFICATE-----".into());
        assert_eq!(
            DispatchRuntimePool::new(pinned_but_plaintext).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "dispatch pool with a pinned root CA requires sslmode=require"
            ))
        );
        let mut plaintext_but_tls = config();
        plaintext_but_tls.postgres_url = plaintext_but_tls
            .postgres_url
            .replace("sslmode=disable", "sslmode=require");
        assert_eq!(
            DispatchRuntimePool::new(plaintext_but_tls).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "dispatch pool without TLS material requires sslmode=disable"
            ))
        );
        let mut prefer = config();
        prefer.postgres_url = prefer.postgres_url.replace("?sslmode=disable", "");
        assert_eq!(
            DispatchRuntimePool::new(prefer).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "dispatch pool without TLS material requires sslmode=disable"
            ))
        );
    }

    #[test]
    fn bounded_execution_preamble_sets_both_local_timeouts() {
        let pool = DispatchRuntimePool::new(config()).expect("pool");
        assert_eq!(
            pool.bounded_execution_preamble(),
            "SET LOCAL statement_timeout = '2000ms'; SET LOCAL lock_timeout = '1000ms';"
        );
        assert_eq!(pool.operation_timeout(), Duration::from_millis(3_000));
    }

    #[tokio::test]
    /// Saturation itself needs a real database to hold a lease against, so it is proved in the live
    /// tier instead: `dispatch_client_live.rs` runs the retry coverage on a `pool_max = 1` pool, and
    /// a lease held across the backoff surfaces there as `Pool(PoolExhausted)`.
    async fn acquire_fails_closed_when_the_cell_database_is_unreachable() {
        let mut value = config();
        value.pool_max = 1;
        value.acquire_timeout = Duration::from_millis(20);
        let pool = DispatchRuntimePool::new(value).expect("pool");
        assert!(matches!(
            pool.acquire().await.err(),
            Some(DispatchPoolError::ConnectFailed | DispatchPoolError::ConnectTimeout)
        ));
    }
}
