// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Prepared-statement caching for the domain pool's hot statements (WP-115
//! row 80, idea 3).
//!
//! # What it saves
//!
//! `tokio-postgres` runs `client.query("...", params)` as two round trips: a
//! Parse/Describe to prepare a fresh named statement, then Bind/Execute. A
//! domain transaction such as `commit_publication` runs about a dozen such
//! statements while it holds the head lock, so the parse round trips are a
//! large share of its hold time. The `*_cached` methods here prepare a
//! statement once per connection, through deadpool's per-connection
//! [`StatementCache`], and run every later call as one Bind/Execute round
//! trip. The SQL text is unchanged; the call site still owns it.
//!
//! # Why no generic plan can occur
//!
//! A cached statement is executed many times, and the server's default
//! `plan_cache_mode = auto` may switch it to a **generic** plan after five
//! executions. A generic plan cannot prove that a bound state parameter
//! (`l.state = ANY($7)`) implies a partial index's predicate, so it can lose
//! the index and scan the table (INV-FJ). Before this change every call
//! prepared a new statement and executed it once, so it always got a custom
//! plan. Every pooled connection now runs with
//! `plan_cache_mode = force_custom_plan` ([`apply_plan_cache_mode`], set by
//! [`crate::pool::build_pool_named`]'s `post_create` hook), so a cached
//! statement is still planned per execution with its actual parameters,
//! exactly as before. The planner never builds a generic plan for it.
//!
//! The setting is session state. Deadpool's `RecyclingMethod::Fast` does not
//! reset session state (only `Clean` runs `DISCARD ALL`), and no code in this
//! workspace runs `RESET`/`DISCARD`, so a recycled connection keeps it. The
//! hook runs on every new connection and fails the connection if the server
//! does not report the mode back, so a connection without it is never handed
//! out: the checkout fails instead.
//!
//! # Why the cache is bounded
//!
//! Every method takes the SQL as `&'static str`. A `format!`-built statement
//! cannot be passed, so the set of distinct cached statements is the set of
//! literal call sites, and each connection caches at most that many.
//!
//! # A result-type change after DDL
//!
//! A booting sibling replica may run `ensure_schema` DDL while this one serves.
//! The server re-plans a cached statement after DDL, and fails it only if its
//! result type changed (`0A000`, "cached plan must not change result type").
//! Deadpool does not drop a failed statement, so that error would repeat on
//! the connection. The methods here evict the statement on that error; the
//! next call prepares it again. The hot statements name their columns rather
//! than `*`, so an added column cannot change their result type.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Mutex;
use std::sync::PoisonError;

use deadpool_postgres::ClientWrapper;
use deadpool_postgres::StatementCache;
use tokio_postgres::Error;
use tokio_postgres::Row;
use tokio_postgres::Statement;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::ToSql;

/// The `plan_cache_mode` every pooled connection runs with.
pub const PLAN_CACHE_MODE: &str = "force_custom_plan";

const SET_PLAN_CACHE_MODE: &str = "SET plan_cache_mode = force_custom_plan";

/// Every distinct statement text the `*_cached` methods have prepared in this
/// process. Bounded by the number of literal call sites.
static PREPARED: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());

/// Set `plan_cache_mode` on a new connection and confirm the server reports
/// it back. An error here fails the connection, so it is never pooled.
///
/// It is a `SET` after connecting rather than a startup `options=-c ...`
/// parameter, so it also works through a session-mode pooler, and so a
/// dropped startup option cannot fail silently: the `SHOW` reads back what
/// the session actually runs with.
///
/// # Errors
///
/// The `SET` or `SHOW` failed, or the server reports a different mode.
pub async fn apply_plan_cache_mode(client: &tokio_postgres::Client) -> Result<(), String> {
    client
        .batch_execute(SET_PLAN_CACHE_MODE)
        .await
        .map_err(|error| format!("postgres session plan_cache_mode: {error}"))?;
    let mode = show_plan_cache_mode(client).await?;
    if mode != PLAN_CACHE_MODE {
        return Err(format!(
            "postgres session plan_cache_mode is {mode}, expected {PLAN_CACHE_MODE}"
        ));
    }
    Ok(())
}

/// The session's current `plan_cache_mode`.
///
/// # Errors
///
/// The `SHOW` failed or returned no text.
pub async fn show_plan_cache_mode(client: &tokio_postgres::Client) -> Result<String, String> {
    client
        .query_one("SHOW plan_cache_mode", &[])
        .await
        .map_err(|error| format!("postgres SHOW plan_cache_mode: {error}"))?
        .try_get::<_, String>(0)
        .map_err(|error| format!("postgres SHOW plan_cache_mode column: {error}"))
}

/// Every distinct statement text the `*_cached` methods have prepared in this
/// process, sorted. For tests: a live test drives the hot paths, then plans
/// each statement this returns.
pub fn prepared_statements() -> Vec<&'static str> {
    PREPARED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .copied()
        .collect()
}

fn record_prepared(sql: &'static str) {
    PREPARED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(sql);
}

/// Drop `sql` from `cache` if the server refused it for a changed result type,
/// so the next call prepares it again.
fn evict_if_stale<T>(cache: &StatementCache, sql: &str, result: &Result<T, Error>) {
    if let Err(error) = result
        && error.code() == Some(&SqlState::FEATURE_NOT_SUPPORTED)
    {
        drop(cache.remove(sql, &[]));
    }
}

/// `query`, `query_one`, `query_opt` and `execute` over a statement prepared
/// once per connection. See the module docs for the plan and bound arguments.
///
/// Implemented for deadpool's client and transaction, which carry the cache,
/// and for a bare `tokio_postgres::Transaction`, which has none: there the
/// methods prepare per call exactly as `query` does. That arm exists so a
/// helper shared with a caller holding only the inner transaction (the
/// creation-metadata path) can stay one function; it caches nothing.
pub trait CachedStatements: Sync {
    /// Rows of `sql`.
    fn query_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Vec<Row>, Error>> + Send + 'a;

    /// The one row of `sql`.
    fn query_one_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Row, Error>> + Send + 'a;

    /// The row of `sql`, if any.
    fn query_opt_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Option<Row>, Error>> + Send + 'a;

    /// Rows `sql` affected.
    fn execute_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<u64, Error>> + Send + 'a;
}

/// Prepare `sql` through `$self`'s cache, recording it the first time it is
/// prepared on any connection.
macro_rules! prepare_cached {
    ($self:ident, $sql:ident) => {{
        let before = $self.statement_cache.size();
        let statement: Statement = $self.prepare_cached($sql).await?;
        if $self.statement_cache.size() > before {
            record_prepared($sql);
        }
        statement
    }};
}

macro_rules! cached_statements_with_cache {
    ($($ty:ty),+) => {$(
        impl CachedStatements for $ty {
            fn query_cached<'a>(
                &'a self,
                sql: &'static str,
                params: &'a [&'a (dyn ToSql + Sync)],
            ) -> impl Future<Output = Result<Vec<Row>, Error>> + Send + 'a {
                async move {
                    let statement = prepare_cached!(self, sql);
                    let result = self.query(&statement, params).await;
                    evict_if_stale(&self.statement_cache, sql, &result);
                    result
                }
            }

            fn query_one_cached<'a>(
                &'a self,
                sql: &'static str,
                params: &'a [&'a (dyn ToSql + Sync)],
            ) -> impl Future<Output = Result<Row, Error>> + Send + 'a {
                async move {
                    let statement = prepare_cached!(self, sql);
                    let result = self.query_one(&statement, params).await;
                    evict_if_stale(&self.statement_cache, sql, &result);
                    result
                }
            }

            fn query_opt_cached<'a>(
                &'a self,
                sql: &'static str,
                params: &'a [&'a (dyn ToSql + Sync)],
            ) -> impl Future<Output = Result<Option<Row>, Error>> + Send + 'a {
                async move {
                    let statement = prepare_cached!(self, sql);
                    let result = self.query_opt(&statement, params).await;
                    evict_if_stale(&self.statement_cache, sql, &result);
                    result
                }
            }

            fn execute_cached<'a>(
                &'a self,
                sql: &'static str,
                params: &'a [&'a (dyn ToSql + Sync)],
            ) -> impl Future<Output = Result<u64, Error>> + Send + 'a {
                async move {
                    let statement = prepare_cached!(self, sql);
                    let result = self.execute(&statement, params).await;
                    evict_if_stale(&self.statement_cache, sql, &result);
                    result
                }
            }
        }
    )+};
}

cached_statements_with_cache!(ClientWrapper, deadpool_postgres::Transaction<'_>);

impl CachedStatements for tokio_postgres::Transaction<'_> {
    fn query_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Vec<Row>, Error>> + Send + 'a {
        self.query(sql, params)
    }

    fn query_one_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Row, Error>> + Send + 'a {
        self.query_one(sql, params)
    }

    fn query_opt_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Option<Row>, Error>> + Send + 'a {
        self.query_opt(sql, params)
    }

    fn execute_cached<'a>(
        &'a self,
        sql: &'static str,
        params: &'a [&'a (dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<u64, Error>> + Send + 'a {
        self.execute(sql, params)
    }
}
