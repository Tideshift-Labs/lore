// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Migration/runtime parity for CR-029's domain tables (WP-116 Phase 2).
//!
//! Applies `lore-postgres/migrations/0001_init.sql` wholesale to one throwaway
//! database, boots `PostgresDomainStore::connect` (the real
//! schema+mediated+outbox `ensure_schema` path) against a second, and
//! compares their `lore_domain_*`/`lore_outbox_*` catalog shape — tables,
//! columns (name/type/nullability/default), constraints (via
//! `pg_get_constraintdef`, which normalises to Postgres's parsed
//! representation rather than raw DDL text, so this only fails on a real
//! semantic difference), and indexes. They must be byte-for-byte equivalent
//! per the crate's own "two declarations, one shape" rule.
//!
//! Gated on `LORE_TEST_PG_URL`; needs `CREATEDB` privilege on that role.
//! Creates and drops two throwaway databases (`lore_wp116_parity_*`) on the
//! same instance — this test genuinely needs two databases, unlike the rest
//! of the WP-116 suite, which shares `lore_domain_*` rows via random
//! identities on one database.

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;

/// The migration file WP-116 Phase 2 keeps in lockstep with the three
/// `domain/*schema*.rs` DDL consts. A real file (not a moving in-flight
/// contract), so `include_str!` is the right tool: if it moves, the crate
/// itself fails to build, not just this test.
const MIGRATIONS_0001: &str = include_str!("../migrations/0001_init.sql");

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn pg_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test setup");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

fn replace_dbname(url: &str, db_name: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let last_slash = base
        .rfind('/')
        .expect("postgres URL must have a /dbname path");
    let mut new_url = format!("{}/{}", &base[..last_slash], db_name);
    if let Some(q) = query {
        new_url.push('?');
        new_url.push_str(q);
    }
    new_url
}

async fn create_throwaway_database(admin_url: &str, label: &str) -> (String, String) {
    let client = pg_client(admin_url).await;
    let suffix: u64 = rand::random();
    let db_name = format!("lore_wp116_parity_{label}_{suffix:016x}");
    client
        .batch_execute(&format!("CREATE DATABASE \"{db_name}\""))
        .await
        .expect("create throwaway database");
    (db_name.clone(), replace_dbname(admin_url, &db_name))
}

async fn drop_throwaway_database(admin_url: &str, db_name: &str) {
    let client = pg_client(admin_url).await;
    let _ = client
        .execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
            &[&db_name],
        )
        .await;
    client
        .batch_execute(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
        .await
        .expect("drop throwaway database");
}

/// One domain/outbox table's full shape, rendered as sorted lines so a diff
/// between two snapshots is directly readable in a test failure message.
async fn table_snapshot(client: &tokio_postgres::Client, table: &str) -> Vec<String> {
    let mut lines = Vec::new();

    let columns = client
        .query(
            "SELECT column_name, data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1 \
             ORDER BY column_name",
            &[&table],
        )
        .await
        .expect("read columns");
    for row in columns {
        let name: String = row.get("column_name");
        let data_type: String = row.get("data_type");
        let nullable: String = row.get("is_nullable");
        let default: Option<String> = row.get("column_default");
        lines.push(format!(
            "{table}::column::{name}::{data_type}::nullable={nullable}::default={default:?}"
        ));
    }

    let constraints = client
        .query(
            "SELECT conname, pg_get_constraintdef(oid) AS def \
             FROM pg_constraint \
             WHERE conrelid = ('public.' || $1)::regclass \
             ORDER BY conname",
            &[&table],
        )
        .await
        .expect("read constraints");
    for row in constraints {
        let name: String = row.get("conname");
        let def: String = row.get("def");
        lines.push(format!("{table}::constraint::{name}::{def}"));
    }

    let indexes = client
        .query(
            "SELECT indexname, indexdef FROM pg_indexes \
             WHERE schemaname = 'public' AND tablename = $1 \
             ORDER BY indexname",
            &[&table],
        )
        .await
        .expect("read indexes");
    for row in indexes {
        let name: String = row.get("indexname");
        let def: String = row.get("indexdef");
        lines.push(format!("{table}::index::{name}::{def}"));
    }

    lines
}

/// The full catalog snapshot: every `lore_domain_*`/`lore_outbox_*` table plus
/// its columns/constraints/indexes, as one sorted, diffable set of lines.
async fn domain_catalog_snapshot(client: &tokio_postgres::Client) -> Vec<String> {
    let tables = client
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' \
               AND (table_name LIKE 'lore_domain_%' OR table_name LIKE 'lore_outbox_%') \
             ORDER BY table_name",
            &[],
        )
        .await
        .expect("list domain/outbox tables");

    let mut snapshot = Vec::new();
    for row in &tables {
        let name: String = row.get("table_name");
        snapshot.push(format!("table::{name}"));
    }
    for row in tables {
        let name: String = row.get("table_name");
        snapshot.extend(table_snapshot(client, &name).await);
    }
    snapshot.sort();
    snapshot
}

/// The Phase 2 gate: `migrations/0001_init.sql` applied wholesale to an empty
/// database must produce the identical `lore_domain_*`/`lore_outbox_*`
/// catalog shape as `PostgresDomainStore::connect`'s boot-time path on a
/// second empty database.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn migration_file_and_boot_time_ensure_schema_produce_identical_domain_catalogs() {
    let Some(admin_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping migration/runtime parity test");
        return;
    };

    let (migration_db, migration_url) = create_throwaway_database(&admin_url, "migration").await;
    let (runtime_db, runtime_url) = create_throwaway_database(&admin_url, "runtime").await;

    let migration_client = pg_client(&migration_url).await;
    migration_client
        .batch_execute(MIGRATIONS_0001)
        .await
        .expect("apply migrations/0001_init.sql wholesale to the migration-side database");

    let _runtime_store = PostgresDomainStore::connect(&runtime_url, 2, &TlsConfig::default())
        .await
        .expect("boot PostgresDomainStore against the runtime-side database");
    let runtime_client = pg_client(&runtime_url).await;

    let migration_snapshot = domain_catalog_snapshot(&migration_client).await;
    let runtime_snapshot = domain_catalog_snapshot(&runtime_client).await;

    if migration_snapshot != runtime_snapshot {
        let only_in_migration: Vec<_> = migration_snapshot
            .iter()
            .filter(|l| !runtime_snapshot.contains(l))
            .collect();
        let only_in_runtime: Vec<_> = runtime_snapshot
            .iter()
            .filter(|l| !migration_snapshot.contains(l))
            .collect();
        panic!(
            "migrations/0001_init.sql and PostgresDomainStore::connect produced different \
             domain/outbox catalogs.\nOnly in migrations/0001_init.sql ({} lines):\n{}\n\n\
             Only in the boot-time ensure_schema path ({} lines):\n{}",
            only_in_migration.len(),
            only_in_migration
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            only_in_runtime.len(),
            only_in_runtime
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    drop(migration_client);
    drop(runtime_client);
    drop_throwaway_database(&admin_url, &migration_db).await;
    drop_throwaway_database(&admin_url, &runtime_db).await;
}
