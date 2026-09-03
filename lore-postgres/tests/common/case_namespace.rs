// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-118 Phase 9: per-case resource namespacing.
//!
//! WP-109 requires every real-service run and test case to own a unique
//! database *or schema* plus a unique bucket/object-prefix namespace
//! (`lorehub/docs/work-packages/wp-109-shared-backend-multi-instance-proof.md`).
//! This module hands one case a single owned token and derives every resource
//! name from it, so a caller cannot namespace one resource kind and forget the
//! other.
//!
//! # Which half of WP-109's rule this implements, and why
//!
//! The `lore-postgres` live runners already give each case a fresh **database**
//! (`run-fragment-lifecycle-live.ps1`, `run-domain-maintenance-live.ps1`,
//! `run-lock-fencing-live.ps1` each `CREATE DATABASE` per case and drop it
//! afterwards). That is one arm of "unique database or schema", and it is
//! PowerShell, so nothing outside those runners can call it.
//!
//! WP-109 Phase 2 needs the *other* arm: it opens two independently
//! constructed coordinator sets against **one** database and **one** bucket, so
//! it cannot use a database per case. This module is the schema arm, callable
//! from Rust by any harness.
//!
//! # How the schema namespace reaches the code under test
//!
//! `lore-postgres`'s DDL is entirely unqualified -- there is no `search_path`
//! or `CREATE SCHEMA` anywhere in `src/` or `migrations/`, and no
//! `CREATE EXTENSION` or `public.`-qualified reference -- so every relation
//! lands in whatever `search_path` resolves to. [`CaseNamespace::pg_url`]
//! appends a libpq `options=-c search_path=<schema>` parameter, which
//! `tokio_postgres::Config` parses and percent-decodes. Every entry point in
//! this crate builds its connection from that URL
//! (`pool::build_pool` parses it with `url.parse::<tokio_postgres::Config>()`,
//! and `PostgresDomainStore::connect` goes through `build_pool`), so the
//! namespace applies with no production change.
//!
//! The `search_path` is the case schema **alone**, not `<schema>, public`. A
//! trailing `public` would let a case read rows another case left there, which
//! is the isolation this exists to provide.
//!
//! # Stated limitation: this does not buy parallel bootstrap
//!
//! `pool::ensure_schema` takes a fixed-key `pg_advisory_xact_lock`
//! (`SCHEMA_LOCK_KEY`) so concurrent replica boots cannot race its
//! `IF NOT EXISTS` DDL. That advisory lock is **database-wide, not
//! schema-scoped**. So two cases bootstrapping into different schemas of the
//! same database serialise on it: schema namespacing gives isolation, but it
//! does not give parallel schema installation.
//!
//! This matters to WP-109 specifically, because its Phase 2 text rules out the
//! separate-database alternative that would avoid the shared lock. Steady-state
//! work after bootstrap is unaffected -- the lock is held only for the duration
//! of the `ensure_schema` transaction.
//!
//! # Cleanup
//!
//! [`CaseNamespace::release`] drops the schema. A namespace dropped without
//! `release` (a panicking case, most often) prints a `retained for debug` line
//! naming the schema, which is WP-109's required disposition for a cleanup that
//! could not complete. Under the live runners the containing database is
//! dropped afterwards regardless, so a retained schema costs nothing beyond the
//! run.

// This module is shared by `#[path]` include. An including file is not expected
// to use every accessor -- `object_prefix` in particular has no consumer in
// this crate at all (see its own docs) -- so per-item `expect(dead_code)` would
// fire or misfire depending on which file included it.
#![allow(dead_code)]

use tokio_postgres::Client;
use uuid::Uuid;

/// Every resource name this module mints starts with this, so a leaked schema
/// in a shared database is identifiable as a test namespace on sight.
const NAMESPACE_PREFIX: &str = "c0ns";

/// Bytes of the caller's label kept in the schema name. The rest of the budget
/// goes to the uniqueness suffix; PostgreSQL truncates an identifier at 63
/// bytes, and silently, which would defeat the whole point.
const MAX_LABEL_BYTES: usize = 12;

/// One case's owned resource namespace.
///
/// Hold it for the lifetime of the case and `release` it at the end. See the
/// module docs for what it does and does not isolate.
pub struct CaseNamespace {
    schema: String,
    pg_url: String,
    object_prefix: String,
    /// Connection to the *base* database with no `search_path` override, kept
    /// for the lifetime of the namespace so `release` and `schemas_containing`
    /// do not depend on the case's own pool still being alive.
    admin: Client,
    released: bool,
}

impl CaseNamespace {
    /// Create this case's schema and derive its resource names.
    ///
    /// `base_url` is the shared database URL (the runners' `LORE_TEST_PG_URL`).
    /// `case_label` is a human hint for debugging a leaked schema; it is
    /// sanitised and truncated, and contributes nothing to uniqueness.
    ///
    /// Panics on a setup failure, matching this crate's live-test convention:
    /// a namespace that cannot be created must fail the case loudly rather than
    /// let it run against whatever schema it would otherwise have shared.
    pub async fn acquire(base_url: &str, case_label: &str) -> Self {
        let schema = mint_schema_name(case_label);
        let admin = connect(base_url, "case-namespace admin").await;
        admin
            .execute(&format!("CREATE SCHEMA {schema}"), &[])
            .await
            .unwrap_or_else(|error| panic!("create case schema {schema}: {error}"));
        // WP-109 requires namespace creation to be recorded, not merely to
        // happen. This line is the record.
        //
        // Where it is actually visible, stated precisely because the obvious
        // reading is wrong: every case runs under `--nocapture`, so this reaches
        // the runner's captured output always, but the runner *prints* that
        // output only on FAIL/NOT RUN, or on PASS for a case listed in its
        // `$printOutputCases` (`run-fragment-lifecycle-live.ps1`). So under the
        // live runner a green case's record is captured and discarded, and it
        // surfaces exactly when a failure makes it worth reading. A harness
        // calling this directly -- WP-109's, the intended consumer -- sees it on
        // its own stdout unconditionally.
        println!("case namespace created: schema={schema}");

        let pg_url = namespaced_url(base_url, &schema);
        let object_prefix = format!("{schema}/");
        Self {
            schema,
            pg_url,
            object_prefix,
            admin,
            released: false,
        }
    }

    /// The database URL a case must use. Identical to the base URL except that
    /// it pins `search_path` to this namespace's schema.
    pub fn pg_url(&self) -> &str {
        &self.pg_url
    }

    /// This namespace's PostgreSQL schema name.
    pub fn schema_name(&self) -> &str {
        &self.schema
    }

    /// This namespace's object-storage key prefix, including its trailing `/`.
    ///
    /// Derived from the same token as the schema so one case's Postgres and
    /// object-store resources cannot drift apart.
    ///
    /// **Unproven from this side.** Nothing in `lore-postgres/tests/`
    /// dereferences it. The one test file here that talks to a real bucket is
    /// `immutable_store.rs`, which is in no live runner; every other suite,
    /// including the whole fragment-lifecycle tier, is provider-free and
    /// supplies object keys as plain `FragmentManifest`/`IoObservation` strings
    /// that never reach an object store. It exists because WP-109 needs one
    /// token covering both resource kinds, and its first real use is WP-109's.
    pub fn object_prefix(&self) -> &str {
        &self.object_prefix
    }

    /// Schema names, across the whole database, that currently hold a table
    /// called `relation`.
    ///
    /// Lets a case assert where its DDL actually landed instead of assuming the
    /// `search_path` took effect.
    pub async fn schemas_containing(&self, relation: &str) -> Vec<String> {
        self.admin
            .query(
                "SELECT schemaname FROM pg_tables WHERE tablename = $1 ORDER BY schemaname",
                &[&relation],
            )
            .await
            .unwrap_or_else(|error| panic!("locate relation {relation}: {error}"))
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect()
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
            // Not a failure in itself: a panicking case unwinds past `release`,
            // and the live runners drop the whole database afterwards anyway.
            // WP-109 requires the disposition be stated rather than inferred.
            println!(
                "case namespace retained for debug (not released): schema={}",
                self.schema
            );
        }
    }
}

/// Mint a schema name that is unique, ordered by creation time, and a valid
/// unquoted PostgreSQL identifier.
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
    // UUIDv7, not v4: the timestamp prefix makes a leaked schema's creation
    // order readable straight from its name.
    let schema = format!("{NAMESPACE_PREFIX}_{label}_{}", Uuid::now_v7().simple());

    // A schema name cannot be a bind parameter -- DDL takes no parameters -- so
    // it is interpolated into SQL. Every character is checked here rather than
    // trusting the sanitiser above to have covered the caller's label.
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
/// The value is percent-encoded: `tokio_postgres`'s URL parser splits a
/// parameter on the first `=` and percent-decodes the remainder, so the space
/// and the inner `=` must both be escaped to survive as one `options` value.
fn namespaced_url(base_url: &str, schema: &str) -> String {
    // This appends rather than merges, so a base URL that already carries
    // `options` would yield two of them and the namespace would depend on which
    // one the driver keeps. The live runners never produce such a URL
    // (`run-fragment-lifecycle-live.ps1` builds a bare
    // `postgresql://user@host:port/db`), so this is a guard against a future
    // caller, not a live defect -- but it fails loudly rather than silently
    // handing back a URL whose `search_path` is ambiguous.
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
