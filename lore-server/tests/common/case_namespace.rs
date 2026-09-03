// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step B: per-case resource namespacing for `lore-server`'s own
//! real-Postgres relay tests.
//!
//! This is the same per-case schema-namespacing tool `lore-postgres/tests/common/case_namespace.rs`
//! established for WP-119 Step A (see that file's docs for the full rationale). It is duplicated
//! here rather than shared via a crate dependency because `lore-postgres/tests/` is not a library
//! target `lore-server`'s own `tests/` binaries can depend on -- only `lore-postgres`'s own `src/`
//! is. The content is intentionally byte-identical in behavior: one case acquires one Postgres
//! schema inside the run's shared database (see the harness note below for how that database
//! itself is provisioned), and every relay function this crate calls resolves against it through
//! the same `options=-c search_path=<schema>` URL parameter `lore-postgres::pool::build_pool` and
//! a raw `tokio_postgres::connect` both honor.
//!
//! # This run's database, vs. this module's schema
//!
//! WP-119 Step B's test run creates ONE throwaway database per run (see the module docs on each
//! `event_relay_*.rs` file for the exact `docker exec ... CREATE DATABASE` invocation), and every
//! case inside that run acquires its own schema through this module. That combination gives
//! per-case isolation for parallel `cargo test` execution within one run, without needing a
//! database per case the way `lore-postgres`'s own `run-*-live.ps1` runners do.

#![allow(dead_code)]

use tokio_postgres::Client;
use uuid::Uuid;

/// Every resource name this module mints starts with this, so a leaked schema in a shared
/// database is identifiable as a test namespace on sight.
const NAMESPACE_PREFIX: &str = "wp119b";

/// Bytes of the caller's label kept in the schema name. The rest of the budget goes to the
/// uniqueness suffix; PostgreSQL truncates an identifier at 63 bytes, and silently, which would
/// defeat the whole point.
const MAX_LABEL_BYTES: usize = 12;

/// One case's owned resource namespace.
///
/// Hold it for the lifetime of the case and `release` it at the end.
pub struct CaseNamespace {
    schema: String,
    pg_url: String,
    admin: Client,
    released: bool,
}

impl CaseNamespace {
    /// Create this case's schema and derive its resource names.
    ///
    /// `base_url` is the shared database URL for this test run. `case_label` is a human hint for
    /// debugging a leaked schema; it is sanitised and truncated, and contributes nothing to
    /// uniqueness.
    ///
    /// Panics on a setup failure, matching the fork's live-test convention: a namespace that
    /// cannot be created must fail the case loudly rather than let it run against whatever schema
    /// it would otherwise have shared.
    pub async fn acquire(base_url: &str, case_label: &str) -> Self {
        let schema = mint_schema_name(case_label);
        let admin = connect(base_url, "case-namespace admin").await;
        admin
            .execute(&format!("CREATE SCHEMA {schema}"), &[])
            .await
            .unwrap_or_else(|error| panic!("create case schema {schema}: {error}"));
        println!("case namespace created: schema={schema}");

        let pg_url = namespaced_url(base_url, &schema);
        Self {
            schema,
            pg_url,
            admin,
            released: false,
        }
    }

    /// The database URL a case must use. Identical to the base URL except that it pins
    /// `search_path` to this namespace's schema.
    pub fn pg_url(&self) -> &str {
        &self.pg_url
    }

    /// This namespace's PostgreSQL schema name.
    pub fn schema_name(&self) -> &str {
        &self.schema
    }

    /// Drop this namespace's schema and everything in it.
    pub async fn release(mut self) {
        let schema = self.schema.clone();
        self.admin
            .execute(&format!("DROP SCHEMA {schema} CASCADE"), &[])
            .await
            .unwrap_or_else(|error| panic!("drop case schema {schema}: {error}"));
        self.released = true;
        println!("case namespace released: schema={schema}");
    }
}

impl Drop for CaseNamespace {
    fn drop(&mut self) {
        if !self.released {
            // Not a failure in itself: a panicking case unwinds past `release`, and the run's
            // database is thrown away afterwards regardless.
            println!(
                "case namespace retained for debug (not released): schema={}",
                self.schema
            );
        }
    }
}

/// Mint a schema name that is unique, ordered by creation time, and a valid unquoted PostgreSQL
/// identifier.
fn mint_schema_name(case_label: &str) -> String {
    let label: String = case_label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(MAX_LABEL_BYTES)
        .collect();
    // UUIDv7, not v4: the timestamp prefix makes a leaked schema's creation order readable
    // straight from its name.
    let schema = format!("{NAMESPACE_PREFIX}_{label}_{}", Uuid::now_v7().simple());

    // A schema name cannot be a bind parameter -- DDL takes no parameters -- so it is
    // interpolated into SQL. Every character is checked here rather than trusting the sanitiser
    // above to have covered the caller's label.
    assert!(
        schema
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "minted schema name must be a bare lowercase identifier, got {schema:?}"
    );
    assert!(
        schema.len() <= 63,
        "minted schema name must fit PostgreSQL's 63-byte identifier limit, got {} bytes",
        schema.len()
    );
    schema
}

/// Append a `search_path` override to `base_url`.
///
/// The value is percent-encoded: `tokio_postgres`'s URL parser splits a parameter on the first
/// `=` and percent-decodes the remainder, so the space and the inner `=` must both be escaped to
/// survive as one `options` value.
fn namespaced_url(base_url: &str, schema: &str) -> String {
    assert!(
        !base_url.contains("options="),
        "base URL already carries an `options` parameter, which this would duplicate: {base_url}",
    );
    let separator = if base_url.contains('?') { '&' } else { '?' };
    format!("{base_url}{separator}options=-c%20search_path%3D{schema}")
}

async fn connect(url: &str, label: &'static str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap_or_else(|error| panic!("connect {label}: {error}"));
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("{label} connection error: {error}");
        }
    });
    client
}
