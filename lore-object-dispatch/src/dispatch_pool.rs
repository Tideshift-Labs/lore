// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! The separately credentialed dispatch-runtime connection pool (WP-114 CD-3), one of the
//! steady-state pools against a cell database.
//!
//! CR-033 D1 made the cell's own PostgreSQL database the dispatch authority. Every retained
//! mutation asserts `session_user = 'object_dispatch_retention_runtime'` and grants `EXECUTE` only
//! to that role, and 0020's enrollment asserts the maintenance role, so `lore-postgres`'s
//! immutable, mutable, lock, and domain pools cannot carry these calls. This module owns the
//! dispatch pool, its credential identity check, and its bounded-execution settings, and it also
//! carries [`DispatchConnectionBudget`], the arithmetic every pool in the process is checked
//! against — including CR-032's event-relay pool, which this module does not own.
//!
//! The opt-in Phase 5 `fragment_provider` composition constructs one shared runtime pool after
//! configuration, process-budget, and lifecycle preflight. The pool itself still installs no
//! schema and publishes no configuration. Constructing it opens connections only to the database
//! named by its caller and enforces the caller's expected physical database identity.

use std::fmt;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use lore_telemetry::AcquireGuard;
use lore_telemetry::AcquireOutcome;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::PoolAcquireMetrics;
use lore_telemetry::PoolAcquireSnapshot;
use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio_postgres::Client;
use tokio_postgres::config::Host;
use tokio_postgres::config::SslMode;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;

use crate::dispatch_client::DATABASE_IDENTITY_SQL;
use crate::dispatch_client::DispatchDatabaseIdentity;
use crate::dispatch_client::DispatchDatabaseIdentityError;
use crate::dispatch_client::decode_database_identity;

/// Shares `lore-postgres`'s metric namespace on purpose: an operator reading a
/// cell's acquisition p95 wants all six pools under one metric name, separated
/// by the `pool` label, not this one under a name of its own.
struct DispatchPoolInstrumentProvider;

impl InstrumentProvider for DispatchPoolInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.store.postgres"
    }
}

/// The PostgreSQL role every 0013/0015/0017 mutation and 0020 registration asserts.
pub const DISPATCH_RUNTIME_ROLE: &str = "object_dispatch_retention_runtime";

/// The PostgreSQL role 0020's participant enrollment asserts.
pub const DISPATCH_MAINTENANCE_ROLE: &str = "object_dispatch_retention_maintenance";

/// Hard ceiling for all PostgreSQL pools one loreserver process opens against its cell database.
pub const DISPATCH_PROCESS_CONNECTION_LIMIT: u32 = 20;

/// The connection-budget statement this pool is sized against, stated rather than implied.
///
/// CR-033 D1 makes the cell database the dispatch authority. A loreserver replica therefore opens
/// this pool beside `lore-postgres`'s immutable, mutable, lock, and domain pools, and beside
/// CR-032's relay pool when `[outbox_relay]` is enabled. All of them target the same cell database
/// and none coordinate on connections, so the process ceiling is the sum of their independently
/// configured maxima, not a shared or inferred `pool_max`.
///
/// This is `lorehub/docs/learnings/do-managed-pg-connection-budget.md`'s finding: a managed
/// instance sized for the app pools alone rather than the full consumer set was exhausted at
/// `max_connections = 25`, and the exhaustion surfaced as SQLSTATE `53300` in three
/// unrelated-looking failures rather than as an obvious pool error.
///
/// # Two pools outside this sum, 2026-09-21
///
/// Verified at their construction sites, and they are not the same kind of exclusion.
///
/// `colocation_check` (`lore-server/src/plugins/postgres.rs:1637`, `pool_max` 1) is **in-process**
/// and opens at startup: `assert_domain_store_colocated` builds it to read
/// `(system_identifier, database OID)` once, then drops it. It is therefore concurrent with the
/// domain pool it is checking against. It does **not** raise the process peak on a cell that
/// configures a fragment provider, because it is released before the dispatch pool opens and
/// `dispatch_pool_max` is then at least 1. It **does** raise the peak to `sum + 1` on a cell with
/// no fragment provider, where `dispatch_pool_max` is zero and nothing later reclaims the
/// headroom — which is exactly the staging profile. A configuration summing to precisely 20 on
/// such a cell momentarily wants 21. That load-bearing ordering claim (colocation released before
/// dispatch construction) is read from source and has not been confirmed by a runtime connection
/// count.
///
/// The event-operator relay pool (`lore-server/src/domain/event_operator.rs:95`, `pool_max` 2)
/// is an out-of-band operator command, `loreserver domain initialize-events`. It belongs to the
/// same class as 0020's enrollment and the schema installer, already carved out below, and is
/// named here only because an unnamed carve-out is indistinguishable from an oversight.
///
/// `PostgresReceiverStore` is **not** a third pool. It holds a `deadpool` `Pool` handle cloned
/// from the relay pool (`lore-server/src/event_relay/wiring.rs:326`), and a clone shares one
/// underlying pool, so it borrows per call and adds nothing. Reserving for it would reserve
/// connections that are never opened. It is, however, a borrower that `RELAY_POOL_MAX`'s own
/// sizing comment (`wiring.rs:108-111`, "one each and one spare" for four borrowers) does not
/// count — a relay sizing question, not a budget question, and not measured here.
pub const DISPATCH_CONNECTION_BUDGET_STATEMENT: &str = "\
Per loreserver process in a cell: lore-postgres immutable, mutable, lock, and domain pools, one \
lore-object-dispatch dispatch-runtime pool, and CR-032's event-relay pool when [outbox_relay] is \
enabled, all against the same cell database and none coordinating on connections. Composition \
must add the six independently configured maxima and refuse a sum above 20 PostgreSQL \
connections before constructing the dispatch pool. The relay's maximum is zero exactly when the \
relay is disabled, so a cell that has not enabled it reserves nothing for it. One further \
in-process connection is NOT in this sum: the startup colocation identity check opens a \
single-connection pool beside the domain pool and releases it before the dispatch pool is built, \
so it is covered by dispatch headroom on a provider-configured cell but raises the momentary peak \
to the sum plus one on a cell with no fragment provider. Size for that one extra connection on \
such a cell. Out-of-band operator commands, including schema install, 0020 enrollment, and \
domain initialize-events, account for their own connections separately and are outside this sum. \
The managed instance must be sized for that total across every replica plus every other consumer \
of the same instance, per lorehub/docs/learnings/do-managed-pg-connection-budget.md.";

/// The per-replica pool arithmetic behind [`DISPATCH_CONNECTION_BUDGET_STATEMENT`].
///
/// Its fields are private so composition cannot bypass the checked constructor or omit a pool by
/// silently declaring zero. A maintenance pool is not part of this steady-state inventory: 0020's
/// enrollment is an out-of-band operator action, like the schema installer, and must account for
/// its own connection separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchConnectionBudget {
    immutable_pool_max: u32,
    mutable_pool_max: u32,
    lock_pool_max: u32,
    domain_pool_max: u32,
    dispatch_pool_max: u32,
    relay_pool_max: u32,
    connections_per_replica: u32,
}

impl DispatchConnectionBudget {
    /// Validate an exact process inventory before any dispatch pool or connection is constructed.
    ///
    /// Three components may be zero, and zero is a statement rather than an
    /// omission: it means this process does not open that pool at all.
    /// `dispatch_pool_max` is zero when no fragment provider is configured,
    /// `relay_pool_max` when `[outbox_relay]` is disabled, and `lock_pool_max`
    /// when the lock store is not in Postgres mode. None of those pools exists
    /// on such a process, so reserving for one would refuse a configuration
    /// that is genuinely inside the budget.
    ///
    /// The immutable, mutable, and domain pools may not be zero. A
    /// Postgres-mode process opens all three unconditionally — the domain pool
    /// is sized from the mutable store's own configuration — so a zero there is
    /// a caller that forgot to declare one rather than a process that does
    /// without it.
    ///
    /// A zero dispatch maximum cannot be turned into a pool by accident:
    /// [`DispatchRuntimePool::new`] refuses a `pool_max` of zero and separately
    /// refuses one that does not equal this declared maximum, so the two checks
    /// together make a dispatch pool unconstructible under a zero budget.
    pub fn new(
        immutable_pool_max: u32,
        mutable_pool_max: u32,
        lock_pool_max: u32,
        domain_pool_max: u32,
        dispatch_pool_max: u32,
        relay_pool_max: u32,
    ) -> Result<Self, DispatchPoolError> {
        if [immutable_pool_max, mutable_pool_max, domain_pool_max].contains(&0) {
            return Err(DispatchPoolError::InvalidConfiguration(
                "every declared process pool maximum must be positive",
            ));
        }

        let connections_per_replica = immutable_pool_max
            .checked_add(mutable_pool_max)
            .and_then(|total| total.checked_add(lock_pool_max))
            .and_then(|total| total.checked_add(domain_pool_max))
            .and_then(|total| total.checked_add(dispatch_pool_max))
            .and_then(|total| total.checked_add(relay_pool_max))
            .ok_or(DispatchPoolError::InvalidConfiguration(
                "process pool inventory overflows the connection count",
            ))?;
        if connections_per_replica > DISPATCH_PROCESS_CONNECTION_LIMIT {
            return Err(DispatchPoolError::InvalidConfiguration(
                "process pool inventory exceeds the hard per-process connection limit",
            ));
        }

        Ok(Self {
            immutable_pool_max,
            mutable_pool_max,
            lock_pool_max,
            domain_pool_max,
            dispatch_pool_max,
            relay_pool_max,
            connections_per_replica,
        })
    }

    pub const fn immutable_pool_max(self) -> u32 {
        self.immutable_pool_max
    }

    pub const fn mutable_pool_max(self) -> u32 {
        self.mutable_pool_max
    }

    pub const fn lock_pool_max(self) -> u32 {
        self.lock_pool_max
    }

    pub const fn domain_pool_max(self) -> u32 {
        self.domain_pool_max
    }

    pub const fn dispatch_pool_max(self) -> u32 {
        self.dispatch_pool_max
    }

    /// Zero when `[outbox_relay]` is disabled, which is the common case today.
    pub const fn relay_pool_max(self) -> u32 {
        self.relay_pool_max
    }

    /// Whether this inventory describes a process that opens a dispatch pool.
    ///
    /// A zero dispatch maximum is a Postgres-mode process with no fragment
    /// provider configured. It still holds the four store and domain pools, and
    /// possibly the relay's, so it is still subject to the ceiling — which is
    /// the whole reason the inventory is built for it.
    #[must_use]
    pub const fn opens_dispatch_pool(self) -> bool {
        self.dispatch_pool_max > 0
    }

    /// Total PostgreSQL connections one loreserver process may hold against the cell database.
    pub const fn connections_per_replica(self) -> u32 {
        self.connections_per_replica
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
    /// Physical cell database every newly opened connection must attest before
    /// it can enter the pool or reach a caller.
    pub expected_database_identity: DispatchDatabaseIdentity,
    /// Concurrent connections this pool may hold. Must exactly match the inventory declaration.
    pub pool_max: u32,
    pub connect_timeout: Duration,
    /// Time a caller waits for a pool slot before failing closed.
    pub acquire_timeout: Duration,
    /// `SET LOCAL statement_timeout` for every transaction the client opens.
    pub statement_timeout: Duration,
    /// `SET LOCAL lock_timeout` for every transaction the client opens.
    pub lock_timeout: Duration,
    pub tls: DispatchTlsMode,
    /// The checked process inventory this pool's `pool_max` is checked against.
    pub budget: DispatchConnectionBudget,
}

impl fmt::Debug for DispatchPoolConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchPoolConfig")
            .field("postgres_url", &"[REDACTED]")
            .field("role", &self.role)
            .field(
                "expected_database_identity",
                &self.expected_database_identity,
            )
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
    #[error("dispatch pool could not read the physical database identity")]
    DatabaseIdentityReadFailed,
    #[error("dispatch pool received a malformed physical database identity")]
    DatabaseIdentityMalformed,
    #[error("dispatch pool connection reached a different physical database")]
    DatabaseIdentityMismatch,
}

/// One pooled PostgreSQL connection.
struct DispatchSession {
    client: Client,
    _connection_task: AbortOnDropHandle<()>,
}

/// The separately credentialed dispatch pool beside the immutable, mutable, lock, and domain
/// pools in the exact six-pool steady-state inventory.
///
/// Connections are opened on demand up to `pool_max` and returned to the idle set when a lease is
/// dropped. A lease the caller marks poisoned is closed rather than reused, which is what the
/// bounded-execution envelope's reconnect-after-ambiguity step needs.
///
/// Runtime consumers share one `Arc<DispatchRuntimePool>`. Cloning that `Arc` adds a client handle,
/// not another pool or another copy of the declared connection budget.
pub struct DispatchRuntimePool {
    config: DispatchPoolConfig,
    permits: Semaphore,
    idle: Mutex<Vec<DispatchSession>>,
    statement_timeout_ms: u64,
    lock_timeout_ms: u64,
    operation_timeout: Duration,
    connections_per_replica: u32,
    acquire_metrics: PoolAcquireMetrics,
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
        let connections_per_replica = config.budget.connections_per_replica();
        if config.pool_max == 0 {
            return Err(DispatchPoolError::InvalidConfiguration(
                "dispatch pool_max must be positive",
            ));
        }
        if config.pool_max != config.budget.dispatch_pool_max() {
            return Err(DispatchPoolError::InvalidConfiguration(
                "dispatch pool_max does not match the declared process inventory",
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
            acquire_metrics: PoolAcquireMetrics::new(&DispatchPoolInstrumentProvider, "dispatch"),
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

    /// Connections one replica may hold across immutable, mutable, lock, domain, and dispatch
    /// pools, per the declared budget.
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
    ///
    /// The wait is measured and recorded under the same `pool_acquire_duration`
    /// instrument `lore-postgres`'s pools use. This pool is hand-rolled rather
    /// than deadpool-backed, so it does not inherit that crate's measured
    /// wrapper and has to time itself; the measurement has to exist here
    /// anyway, because this is the one pool of the six whose exhaustion is a
    /// permit wait rather than a connection wait, and a process-wide
    /// acquisition p95 that silently omitted it would be quoting five pools
    /// while naming six.
    pub(crate) async fn acquire(&self) -> Result<DispatchLease<'_>, DispatchPoolError> {
        // An `AcquireGuard` rather than an `Instant` pair: this future is
        // cancellable at both awaits below (the permit wait and the connect),
        // and a caller dropped at either one has still waited. Recording only
        // on return would lose exactly the longest waits — see
        // `AcquireOutcome::Abandoned`.
        let mut guard = AcquireGuard::new(&self.acquire_metrics);
        let lease = self.acquire_inner().await;
        guard.settle(if lease.is_ok() {
            AcquireOutcome::Acquired
        } else {
            AcquireOutcome::Failed
        });
        lease
    }

    /// Read this pool's acquisition tally in-process, without an OTLP
    /// collector.
    pub fn acquire_snapshot(&self) -> PoolAcquireSnapshot {
        self.acquire_metrics.snapshot()
    }

    async fn acquire_inner(&self) -> Result<DispatchLease<'_>, DispatchPoolError> {
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
        tokio::time::timeout(self.config.connect_timeout, async {
            let (client, connection) = postgres
                .connect(tls)
                .await
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
            attest_open_connection_database_identity(
                &client,
                self.config.expected_database_identity,
            )
            .await?;
            Ok(DispatchSession {
                client,
                _connection_task: connection_task,
            })
        })
        .await
        .map_err(|_| DispatchPoolError::ConnectTimeout)?
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

/// Attest the just-opened physical connection before it becomes a pool
/// session. This exact `Client` is queried and, on any refusal, dropped with
/// its connection task rather than admitted to the idle set or returned to a
/// caller.
async fn attest_open_connection_database_identity(
    client: &Client,
    expected: DispatchDatabaseIdentity,
) -> Result<(), DispatchPoolError> {
    let row = client
        .query_one(DATABASE_IDENTITY_SQL, &[])
        .await
        .map_err(|_| DispatchPoolError::DatabaseIdentityReadFailed)?;
    let actual = decode_database_identity(&row).map_err(|error| match error {
        DispatchDatabaseIdentityError::Malformed => DispatchPoolError::DatabaseIdentityMalformed,
        DispatchDatabaseIdentityError::Mismatch => DispatchPoolError::DatabaseIdentityMismatch,
        DispatchDatabaseIdentityError::Read(_) => DispatchPoolError::DatabaseIdentityReadFailed,
    })?;
    if actual != expected {
        return Err(DispatchPoolError::DatabaseIdentityMismatch);
    }
    Ok(())
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
            expected_database_identity: DispatchDatabaseIdentity::new(1, 1)
                .expect("test physical database identity"),
            pool_max: 5,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_millis(2_000),
            lock_timeout: Duration::from_millis(1_000),
            tls: DispatchTlsMode::Disabled,
            budget: DispatchConnectionBudget::new(1, 2, 3, 4, 5, 0).expect("test process budget"),
        }
    }

    #[test]
    fn exact_six_pool_budget_is_twenty_connections_per_replica() {
        // Six distinct values cannot sum to 20 (1+2+3+4+5+6 is already 21), so
        // one pair must repeat. It is deliberately immutable/mutable rather
        // than domain/dispatch: those two are the pair a constructor argument
        // transposition would most plausibly swap, and equal values there would
        // make this assertion blind to it.
        let budget = DispatchConnectionBudget::new(2, 2, 4, 6, 5, 1).expect("exact process budget");
        assert_eq!(budget.immutable_pool_max, 2);
        assert_eq!(budget.mutable_pool_max, 2);
        assert_eq!(budget.lock_pool_max, 4);
        assert_eq!(budget.domain_pool_max, 6);
        assert_eq!(budget.dispatch_pool_max, 5);
        assert_eq!(budget.relay_pool_max, 1);
        assert_eq!(budget.connections_per_replica(), 20);
    }

    /// Dispatch and relay may be zero, because each pool is opened only on a
    /// cell configured for it. Zero must reserve nothing rather than be refused
    /// as an undeclared pool.
    #[test]
    fn a_zero_relay_pool_is_accepted_and_reserves_nothing() {
        let without =
            DispatchConnectionBudget::new(5, 5, 5, 4, 1, 0).expect("relay-disabled budget");
        assert_eq!(without.relay_pool_max(), 0);
        assert_eq!(without.connections_per_replica(), 20);

        // A provider-disabled cell: no dispatch pool either, and still legal.
        let neither = DispatchConnectionBudget::new(5, 5, 4, 2, 0, 0)
            .expect("provider-disabled and relay-disabled budget");
        assert!(!neither.opens_dispatch_pool());
        assert_eq!(neither.connections_per_replica(), 16);

        // A lock store outside Postgres mode: no lock pool, and still legal.
        assert!(
            DispatchConnectionBudget::new(5, 5, 0, 4, 1, 5).is_ok(),
            "a zero lock pool is a non-Postgres lock store, not an undeclared pool"
        );

        for zero_elsewhere in [
            DispatchConnectionBudget::new(0, 5, 5, 4, 1, 5),
            DispatchConnectionBudget::new(5, 0, 5, 4, 1, 5),
            DispatchConnectionBudget::new(5, 5, 5, 0, 1, 5),
        ] {
            assert_eq!(
                zero_elsewhere.err(),
                Some(DispatchPoolError::InvalidConfiguration(
                    "every declared process pool maximum must be positive"
                )),
                "the three pools a Postgres-mode process always opens may not be zero"
            );
        }
    }

    /// The point of counting the relay at all: a configuration that fits inside
    /// the ceiling with the relay off must refuse once the relay is on.
    ///
    /// The staging loreserver is the live case. Its three store pools at 5 plus
    /// a domain pool at 4 sum to 19, and CR-032's five relay connections take
    /// that to 24. It does not refuse today only because its fragment provider
    /// is off, so no inventory is built and this arithmetic never runs —
    /// enabling both is what makes the refusal real, and retuning those pools
    /// is an operator decision rather than something this crate should paper
    /// over.
    #[test]
    fn a_configuration_inside_the_ceiling_without_the_relay_is_refused_with_it() {
        let relay_off = DispatchConnectionBudget::new(5, 5, 4, 2, 1, 0);
        assert_eq!(
            relay_off
                .expect("17 connections is inside the ceiling")
                .connections_per_replica(),
            17
        );
        assert_eq!(
            DispatchConnectionBudget::new(5, 5, 4, 2, 1, 5).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "process pool inventory exceeds the hard per-process connection limit"
            )),
            "22 connections must be refused before any pool is opened"
        );
    }

    #[test]
    fn pool_max_above_the_declared_budget_is_refused() {
        let mut value = config();
        value.pool_max = 6;
        assert_eq!(
            DispatchRuntimePool::new(value).err(),
            Some(DispatchPoolError::InvalidConfiguration(
                "dispatch pool_max does not match the declared process inventory"
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
        assert_eq!(pool.connections_per_replica(), 15);
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
        value.budget =
            DispatchConnectionBudget::new(1, 2, 3, 4, 1, 0).expect("single-slot test budget");
        value.acquire_timeout = Duration::from_millis(20);
        let pool = DispatchRuntimePool::new(value).expect("pool");
        assert!(matches!(
            pool.acquire().await.err(),
            Some(DispatchPoolError::ConnectFailed | DispatchPoolError::ConnectTimeout)
        ));
    }
}
