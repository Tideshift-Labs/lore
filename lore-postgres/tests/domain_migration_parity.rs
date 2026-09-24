// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Migration/runtime parity for CR-029's domain tables (WP-116 Phase 2).
//!
//! Applies `lore-postgres/migrations/0001_init.sql` wholesale to one throwaway
//! database, boots `PostgresDomainStore::connect` (the real
//! schema+mediated+outbox `ensure_schema` path plus SCHEMA-117's and
//! SCHEMA-118's isolated migration fixtures) against a second, and
//! compares their `lore_domain_*`/`lore_outbox_*`/`lore_fragment_*` catalog shape — tables,
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
use lore_postgres::domain::fragments::schema as fragment_schema;
use lore_postgres::domain::locks::schema as lock_schema;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::lock_store::PostgresLockStore;

/// The migration file WP-116 Phase 2 keeps in lockstep with the three
/// `domain/*schema*.rs` DDL consts. A real file (not a moving in-flight
/// contract), so `include_str!` is the right tool: if it moves, the crate
/// itself fails to build, not just this test.
const MIGRATIONS_0001: &str = include_str!("../migrations/0001_init.sql");

/// L1 (WP-114/WP-115): the first numbered follow-on this crate has ever had
/// (DECISION 3 -- a new file rather than an edit to `0001_init.sql`, so an
/// already-provisioned cell is not silently skipped). Applied wholesale,
/// after `MIGRATIONS_0001`, to the migration-side database below, mirroring
/// what an out-of-band-provisioned cell running both migrations in order
/// actually has.
const MIGRATIONS_0002: &str = include_str!("../migrations/0002_fragment_promotion_send_claims.sql");
const MIGRATIONS_0003: &str = include_str!("../migrations/0003_fragment_stage_custody.sql");
const MIGRATIONS_0004: &str = include_str!("../migrations/0004_fragment_stage_policy_rotation.sql");
/// Contract amendment A-32's event plane marker and retired-row evidence. The
/// boot path applies the same file through `EVENT_PLANE_SCHEMA`.
const MIGRATIONS_0005: &str = include_str!("../migrations/0005_outbox_event_plane.sql");

/// The relations that prove `migrations/0001_init.sql` (or the isolated test
/// fixture) ran here. `lore_locks` is excluded because it also pre-dates
/// SCHEMA-117 on an upgraded cell, so its presence proves nothing either way —
/// not because anything other than SCHEMA-117 creates it.
const SCHEMA_117_RELATIONS: [&str; 4] = [
    "lore_domain_lock_schema_state",
    "lore_domain_lock_namespaces",
    "lore_domain_lock_backfill_quarantine",
    "lore_domain_lock_fence_seq",
];

/// SCHEMA-118's own relation-presence probe (CR-031/WP-118), reused here
/// rather than duplicated. `lore_fragment_fence_seq` is a sequence, not a
/// table, and is deliberately not part of this constant; the catalog snapshot
/// below covers it separately via `pg_sequences`.
fn schema_118_relations() -> Vec<&'static str> {
    fragment_schema::FRAGMENT_SCHEMA_RELATIONS.to_vec()
}

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass")
}

async fn relation_exists(client: &tokio_postgres::Client, relation: &str) -> bool {
    client
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&relation])
        .await
        .expect("probe relation existence")
        .get(0)
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

/// The full catalog snapshot: every domain/outbox table plus the legacy lock
/// table extended by SCHEMA-117, the SCHEMA-118 fragment lifecycle tables, and
/// all domain sequences/functions/triggers.
///
/// SCHEMA-118's tables are matched by their exact `FRAGMENT_SCHEMA_RELATIONS`
/// names, not a `lore_fragment_%` LIKE pattern. The legacy CR-007 immutable
/// store's own self-bootstrap tables (`lore_fragments`, `lore_fragment_state`,
/// `lore_fragment_metering`) also match that prefix and are mirrored into
/// `migrations/0001_init.sql`, but this test's runtime side never constructs a
/// `PostgresImmutableStore` to create them — a LIKE pattern would make the
/// migration snapshot see three tables the runtime snapshot never gets a
/// chance to create, failing on a mismatch this test has no way to close and
/// that has nothing to do with SCHEMA-118 parity.
async fn domain_catalog_snapshot(client: &tokio_postgres::Client) -> Vec<String> {
    let tables = client
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' \
               AND (table_name LIKE 'lore_domain_%' OR table_name LIKE 'lore_outbox_%' \
                    OR table_name = ANY($1) OR table_name = 'lore_locks') \
             ORDER BY table_name",
            &[&schema_118_relations()],
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

    let sequences = client
        .query(
            "SELECT sequencename, start_value, min_value, max_value, increment_by, cycle \
               FROM pg_sequences WHERE schemaname = 'public' \
                AND (sequencename LIKE 'lore_domain_%' OR sequencename = 'lore_fragment_fence_seq') \
              ORDER BY sequencename",
            &[],
        )
        .await
        .expect("list domain sequences");
    for row in sequences {
        let name: String = row.get("sequencename");
        let start: i64 = row.get("start_value");
        let min: i64 = row.get("min_value");
        let max: i64 = row.get("max_value");
        let increment: i64 = row.get("increment_by");
        let cycle: bool = row.get("cycle");
        snapshot.push(format!(
            "sequence::{name}::start={start}::min={min}::max={max}::increment={increment}::cycle={cycle}"
        ));
    }

    let functions = client
        .query(
            "SELECT p.proname, pg_get_functiondef(p.oid) AS def \
               FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace \
              WHERE n.nspname = 'public' AND (p.proname LIKE 'lore_domain_%' \
                 OR p.proname IN ('stage_policy_publish_v1', 'stage_policy_verify_v1', \
                                  'stage_policy_rotate_v1')) \
              ORDER BY p.proname, p.oid",
            &[],
        )
        .await
        .expect("list domain functions");
    for row in functions {
        let name: String = row.get("proname");
        let definition: String = row.get("def");
        snapshot.push(format!("function::{name}::{definition}"));
    }

    let triggers = client
        .query(
            "SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid, true) AS def \
               FROM pg_trigger AS t JOIN pg_class AS c ON c.oid = t.tgrelid \
               JOIN pg_namespace AS n ON n.oid = c.relnamespace \
              WHERE n.nspname = 'public' AND NOT t.tgisinternal \
                AND (c.relname LIKE 'lore_domain_%' OR c.relname = 'lore_locks') \
              ORDER BY c.relname, t.tgname",
            &[],
        )
        .await
        .expect("list domain triggers");
    for row in triggers {
        let table: String = row.get("relname");
        let name: String = row.get("tgname");
        let definition: String = row.get("def");
        snapshot.push(format!("trigger::{table}::{name}::{definition}"));
    }
    snapshot.sort();
    snapshot
}

/// The Phase 2 gate, in the order production actually runs.
///
/// The runtime side boots exactly as `lore-server/src/server.rs` does — the
/// domain store first, the legacy lock-store plugin second — and the test
/// first asserts what that boot does *not* create: every SCHEMA-117 AND
/// SCHEMA-118 relation is still absent, because CR-030 N-7 and CR-031 both
/// keep their DDL migration-owned. Skipping straight to `bootstrap()` proved
/// parity against a fixture production never executes and hid the fact that a
/// booted cell has no fenced schema at all (INV-EE P0-1); CR-031 repeats that
/// exact lesson for fragment lifecycle routing.
///
/// Only then does it install `LOCK_SCHEMA` and `FRAGMENT_SCHEMA` through their
/// isolated fixtures and compare the full catalogs, which is the "two
/// declarations, one shape" claim for both CR-030 and CR-031.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn migration_file_and_boot_time_ensure_schema_produce_identical_domain_catalogs() {
    let admin_url = pg_url();

    let (migration_db, migration_url) = create_throwaway_database(&admin_url, "migration").await;
    let (runtime_db, runtime_url) = create_throwaway_database(&admin_url, "runtime").await;

    let migration_client = pg_client(&migration_url).await;
    migration_client
        .batch_execute(MIGRATIONS_0001)
        .await
        .expect("apply migrations/0001_init.sql wholesale to the migration-side database");
    migration_client
        .batch_execute(MIGRATIONS_0002)
        .await
        .expect(
            "apply migrations/0002_fragment_promotion_send_claims.sql wholesale to the \
             migration-side database, mirroring an out-of-band-provisioned cell that has run \
             both migrations in order",
        );

    migration_client
        .batch_execute(MIGRATIONS_0003)
        .await
        .expect("apply stage custody migration");
    migration_client
        .batch_execute(MIGRATIONS_0004)
        .await
        .expect("apply stage policy rotation migration");
    migration_client
        .batch_execute(MIGRATIONS_0005)
        .await
        .expect("apply event plane migration");

    // Production boot order: the domain coordinator is built before the lock
    // store plugin connects (`server.rs`), so nothing has created `lore_locks`
    // when the coordinator first reads its readiness.
    let runtime_store = PostgresDomainStore::connect(&runtime_url, 2, &TlsConfig::default())
        .await
        .expect("boot PostgresDomainStore against the runtime-side database");
    let runtime_client = pg_client(&runtime_url).await;
    for relation in SCHEMA_117_RELATIONS {
        assert!(
            !relation_exists(&runtime_client, relation).await,
            "the boot-time ensure_schema path must not create the migration-owned \
             SCHEMA-117 relation {relation}"
        );
    }
    // Fenced readiness must be answerable on exactly that state, and must
    // answer "not provisioned" rather than erroring.
    let readiness = runtime_store
        .lock_coordinator()
        .readiness()
        .await
        .expect("readiness on a cell the migration has not reached must not error");
    assert!(!readiness.provisioned);
    assert!(!readiness.fencing_enabled);

    // Same shape, one Lore change request over: SCHEMA-118's fragment
    // lifecycle DDL is migration-owned too (CR-031), kept out of both the
    // legacy immutable store's self-bootstrap and this same
    // `PostgresDomainStore::connect` path, so a cell the migration has not
    // reached must answer "not provisioned" here as well.
    for relation in schema_118_relations() {
        assert!(
            !relation_exists(&runtime_client, relation).await,
            "the boot-time ensure_schema path must not create the migration-owned \
             SCHEMA-118 relation {relation}"
        );
    }
    let fragment_readiness = runtime_store
        .fragment_coordinator()
        .readiness()
        .await
        .expect("fragment readiness on a cell the migration has not reached must not error");
    assert!(!fragment_readiness.provisioned);
    assert!(!fragment_readiness.lifecycle_enabled);

    let _runtime_lock_store = PostgresLockStore::connect(&runtime_url, 2, &TlsConfig::default())
        .await
        .expect("boot the legacy lock store, as the plugin does after the domain store");
    runtime_store
        .lock_coordinator()
        .bootstrap()
        .await
        .expect("install SCHEMA-117 through the isolated runtime fixture");
    runtime_store
        .fragment_coordinator()
        .bootstrap()
        .await
        .expect("install SCHEMA-118 through the isolated runtime fixture");

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

// ---------------------------------------------------------------------------
// Offline premise pins (INV-EF fix-round addendum)
// ---------------------------------------------------------------------------
//
// Three schema facts that Rust guards in `domain/fragments/coordinator.rs`
// silently depend on. Each is a premise, not a preference: if the DDL drifts,
// the guard above it stops being sound while every existing test stays green,
// because nothing else reads these shapes.
//
// These run in the DEFAULT tier -- no `#[ignore]`, no database. The live parity
// case above proves the two declarations AGREE with each other; it cannot prove
// either one still says the thing a Rust invariant was built on. That is what
// these add, and it is why they belong beside it rather than inside it.
//
// Both declarations are checked. `migrations/0001_init.sql` is the
// out-of-band provisioning path and `fragment_schema::FRAGMENT_SCHEMA` is the
// boot-time path; a premise that held in only one of them would be exactly the
// drift the crate's "two declarations, one shape" rule exists to catch.

/// Cut one `CREATE TABLE` body out of a DDL blob so a premise is asserted
/// against the table it belongs to.
///
/// A bare `contains` over the whole file would let `PRIMARY KEY (hash, epoch)`
/// be satisfied by some unrelated table declaring the same pair, which is the
/// failure mode that makes a text pin worthless.
fn create_table_body<'a>(ddl: &'a str, table: &str) -> &'a str {
    let marker = format!("CREATE TABLE IF NOT EXISTS {table} (");
    let start = ddl
        .find(&marker)
        .unwrap_or_else(|| panic!("{table} is not declared in this DDL"));
    let rest = &ddl[start + marker.len()..];
    let end = rest
        .find("\n);")
        .unwrap_or_else(|| panic!("{table}'s CREATE TABLE body is not terminated"));
    &rest[..end]
}

/// Collapse every run of whitespace to one space.
///
/// Every pin in this file matches against this form, so all of them are
/// alignment-tolerant in the same way. The `NOT NULL` loop below already had
/// that property by construction while the `disposition` pin was an exact
/// spacing literal; the two disagreed, and the tolerant direction is the right
/// one because a pin that fails on a column-alignment change is noise, and noise
/// is what gets a pin deleted rather than investigated. Content is still
/// matched exactly — only the spacing between tokens is normalised.
fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The two declarations every premise is asserted against.
fn epoch_declarations() -> [(&'static str, &'static str); 2] {
    [
        ("migrations/0001_init.sql", MIGRATIONS_0001),
        (
            "fragment_schema::FRAGMENT_SCHEMA",
            fragment_schema::FRAGMENT_SCHEMA,
        ),
    ]
}

/// Find one column's declaration line inside a `CREATE TABLE` body.
///
/// Matched by column name at the start of the line rather than by exact
/// spacing, so a realignment of the table is a formatting change and not a test
/// failure. A pin that fails on formatting is noise, and noise is what gets a
/// pin deleted rather than investigated. Content is still asserted exactly by
/// the caller.
fn column_declaration<'a>(ddl: &'a str, table: &str, column: &str, label: &str) -> &'a str {
    create_table_body(ddl, table)
        .lines()
        .find(|line| {
            line.trim_start()
                .strip_prefix(column)
                .is_some_and(|rest| rest.starts_with(' '))
        })
        .unwrap_or_else(|| panic!("{label}: {table} does not declare {column}"))
}

/// Assert one premise against both DDL declarations at once.
fn pin_premise(table: &str, needle: &str, why: &str) {
    for (label, ddl) in [
        ("migrations/0001_init.sql", MIGRATIONS_0001),
        (
            "fragment_schema::FRAGMENT_SCHEMA",
            fragment_schema::FRAGMENT_SCHEMA,
        ),
    ] {
        let body = create_table_body(ddl, table);
        assert!(
            collapse_whitespace(body).contains(&collapse_whitespace(needle)),
            "{label}: {table} must declare `{needle}`.\n{why}\nActual body:\n{body}"
        );
    }
}

/// `validate_lease_members` refuses a batch repeating one hash. That refusal is
/// justified by exactly one thing: the member table holds one row per
/// `(lease_id, hash)`, so a second epoch for the same hash would be dropped by
/// the `ON CONFLICT` arm while the returned lease claimed it. Widen this key
/// and the Rust validation is guarding nothing.
#[test]
fn the_staged_lease_member_key_is_lease_id_and_hash() {
    pin_premise(
        "lore_fragment_staged_lease_members",
        "PRIMARY KEY (lease_id, hash)",
        "coordinator.rs's validate_lease_members refuses a duplicate hash on the strength of \
         this key alone; a wider key makes that refusal meaningless and a narrower one makes it \
         insufficient.",
    );
}

/// `equivalent_epochs` compares `count(*)` from a two-way join against
/// `divergent.len()`. That arithmetic is only sound because `(hash, epoch)`
/// identifies at most one epoch row, so each input row contributes at most one
/// join row. Without the key, a duplicated epoch row would inflate the count
/// and a non-equivalent member could be masked by an equivalent one.
#[test]
fn the_fragment_epoch_key_is_hash_and_epoch() {
    pin_premise(
        "lore_fragment_epochs",
        "PRIMARY KEY (hash, epoch)",
        "coordinator.rs's equivalent_epochs compares a join count against the input length; that \
         is a one-row-per-input assumption and this key is the only thing enforcing it.",
    );
}

/// The four columns `equivalent_epochs` compares must be `NOT NULL`, and
/// `disposition` must stay a closed three-value vocabulary.
///
/// SQL equality over a NULL yields NULL, not true, so a nullable compared
/// column would silently drop rows from the match count and turn an equivalent
/// pair into an abort — failing safe, but for a reason no reader could see. The
/// `disposition` CHECK is what lets the lease scope test `<> DISPOSITION_PURGED`
/// as a total predicate rather than one of an open set.
#[test]
fn the_compared_epoch_columns_are_not_null_and_disposition_stays_closed() {
    for column in [
        "decoded_hash",
        "size_content",
        "size_payload",
        "payload_flags",
    ] {
        for (label, ddl) in epoch_declarations() {
            let line = column_declaration(ddl, "lore_fragment_epochs", column, label);
            assert!(
                line.contains("NOT NULL"),
                "{label}: lore_fragment_epochs.{column} must be NOT NULL. equivalent_epochs \
                 compares it with `=`, and SQL equality over NULL is NULL rather than true, so a \
                 nullable column would silently drop the row from the match count and turn an \
                 equivalent pair into an abort.\nActual: {line}"
            );
        }
    }
    // Matched the same way as the loop above rather than as an exact-spacing
    // literal. The two used to disagree: this one would have broken on a
    // realignment of the CREATE TABLE that its siblings survived, which is the
    // inconsistency N5 named.
    for (label, ddl) in epoch_declarations() {
        let line = column_declaration(ddl, "lore_fragment_epochs", "disposition", label);
        assert!(
            line.contains("NOT NULL"),
            "{label}: lore_fragment_epochs.disposition must be NOT NULL.\nActual: {line}"
        );
        assert!(
            line.contains("CHECK (disposition IN (0, 1, 2))"),
            "{label}: lore_fragment_epochs.disposition must stay closed at exactly (0, 1, 2). \
             acquire_staged_leases scopes members with `disposition <> DISPOSITION_PURGED`, which \
             is a total predicate only while the vocabulary is closed.\nActual: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// SCHEMA-117 amendment (RULING B) offline pins.
//
// `lore_locks` is extended by `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
// rather than one inline `CREATE TABLE` body, so the fragment schema's
// `create_table_body`/`column_declaration` helpers above (built for a single
// contiguous `CREATE TABLE`) don't apply here; these pins match by substring
// instead, which is adequate for a constraint/column *name* fact rather than
// a full column-shape fact.
//
// These run in the DEFAULT tier -- no `#[ignore]`, no database -- mirroring
// `domain/fragments/schema.rs`'s `seed_schema_version_matches_the_constant`
// for a schema module that (being fork-local `lore-postgres`, not
// upstream) cannot host its own `#[cfg(test)]` pin without editing `src/`.

/// Pull the aliased `schema_version` literal out of one DDL body. Mirrors
/// `fragment_schema`'s own private helper of the same name exactly.
fn seeded_schema_version(ddl: &str, source: &str) -> i64 {
    let line = ddl
        .lines()
        .find(|line| line.contains("AS schema_version"))
        .unwrap_or_else(|| {
            panic!("{source} must alias its schema_version literal so this test can find it")
        });
    line.split_whitespace()
        .next()
        .and_then(|token| token.parse().ok())
        .unwrap_or_else(|| {
            panic!("{source}'s aliased schema_version column must lead with an integer literal")
        })
}

/// RULING B: `LOCK_SCHEMA`'s seed literal must equal `LOCK_SCHEMA_VERSION`.
/// `bootstrap()` upgrades an existing row to the constant; the seed for a
/// brand-new database is a raw SQL literal that cannot reference it, so
/// nothing else would notice a version bump applied to one and not the other.
#[test]
fn lock_schema_seed_matches_the_lock_schema_version_constant() {
    let literal = seeded_schema_version(lock_schema::LOCK_SCHEMA, "the LOCK_SCHEMA seed");
    assert_eq!(
        literal,
        lock_schema::LOCK_SCHEMA_VERSION,
        "LOCK_SCHEMA's seed writes schema_version {literal} but bootstrap() upgrades to \
         LOCK_SCHEMA_VERSION = {}; bump both or neither",
        lock_schema::LOCK_SCHEMA_VERSION
    );
}

/// RULING B: `migrations/0001_init.sql` carries the same constraint name and
/// column as the runtime `LOCK_SCHEMA`, and no longer declares the superseded
/// v1 constraint alongside it.
#[test]
fn migrations_0001_carries_the_v2_fenced_shape_constraint_and_never_issued_column() {
    assert!(
        MIGRATIONS_0001.contains("token_never_issued"),
        "migrations/0001_init.sql must declare the token_never_issued column, mirroring LOCK_SCHEMA"
    );
    assert!(
        MIGRATIONS_0001.contains("lore_locks_fenced_shape_v2"),
        "migrations/0001_init.sql must carry the lore_locks_fenced_shape_v2 constraint name, \
         mirroring LOCK_SCHEMA"
    );
    assert!(
        !MIGRATIONS_0001.contains("CONSTRAINT lore_locks_fenced_shape CHECK"),
        "migrations/0001_init.sql must not keep declaring the superseded v1 constraint \
         (lore_locks_fenced_shape) alongside its v2 replacement"
    );
}

/// The runtime side of the same fact: `LOCK_SCHEMA` itself must declare both,
/// so a change made only to the migration file (or only to the runtime
/// constant) is caught here rather than by the live parity gate alone.
#[test]
fn lock_schema_carries_the_v2_fenced_shape_constraint_and_never_issued_column() {
    assert!(
        lock_schema::LOCK_SCHEMA.contains("token_never_issued"),
        "LOCK_SCHEMA must declare the token_never_issued column"
    );
    assert!(
        lock_schema::LOCK_SCHEMA.contains("lore_locks_fenced_shape_v2"),
        "LOCK_SCHEMA must carry the lore_locks_fenced_shape_v2 constraint name"
    );
    assert!(
        !lock_schema::LOCK_SCHEMA.contains("CONSTRAINT lore_locks_fenced_shape CHECK"),
        "LOCK_SCHEMA must not keep declaring the superseded v1 constraint \
         (lore_locks_fenced_shape) alongside its v2 replacement"
    );
}

// ---------------------------------------------------------------------------
// L1 (WP-114/WP-115): the durable promotion send claim's new columns, in
// both declarations, mirroring RULING B's pattern above for an
// `ALTER TABLE ... ADD COLUMN` extension rather than a single contiguous
// `CREATE TABLE` body (so `pin_premise`'s `create_table_body` helper does not
// apply here either).
// ---------------------------------------------------------------------------

/// `0002_fragment_promotion_send_claims.sql` must declare the same claim
/// columns and shape CHECK as the runtime `FRAGMENT_SCHEMA`, or an
/// out-of-band-provisioned cell (this migration's whole reason to exist,
/// DECISION 3) ends up with a claims table an up-to-date binary cannot use.
#[test]
fn migration_0002_declares_the_same_promotion_claim_columns_and_shape_check_as_fragment_schema() {
    let migration = collapse_whitespace(MIGRATIONS_0002);
    let runtime = collapse_whitespace(fragment_schema::FRAGMENT_SCHEMA);
    for needle in [
        "ALTER TABLE lore_fragment_write_claims",
        "ADD COLUMN IF NOT EXISTS kind",
        "CHECK (kind IN (0, 1))",
        "ADD COLUMN IF NOT EXISTS source_epoch",
        "ADD COLUMN IF NOT EXISTS source_manifest_id",
        "octet_length(source_manifest_id) = 32",
        "ADD CONSTRAINT lore_fragment_write_claim_promotion_shape",
        "(kind = 1) = (source_epoch IS NOT NULL)",
        "(kind = 1) = (source_manifest_id IS NOT NULL)",
        "(kind = 0 OR source_epoch < epoch)",
    ] {
        let collapsed_needle = collapse_whitespace(needle);
        assert!(
            migration.contains(&collapsed_needle),
            "migrations/0002_fragment_promotion_send_claims.sql must declare `{needle}`"
        );
        assert!(
            runtime.contains(&collapsed_needle),
            "fragment_schema::FRAGMENT_SCHEMA must declare `{needle}` too, or an already-running \
             cell's idempotent re-apply on every boot never gets it"
        );
    }
}

/// `0002` must be idempotent: Postgres has no `ADD CONSTRAINT IF NOT EXISTS`,
/// so a straight `ADD CONSTRAINT` re-run on an already-migrated cell errors.
/// Applying the same file twice to one throwaway database is the direct,
/// executable proof; a source-text read cannot rule out this failure mode.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn migration_0002_is_idempotent_against_an_already_migrated_database() {
    let admin_url = pg_url();
    let (db_name, url) = create_throwaway_database(&admin_url, "0002idempotent").await;
    let client = pg_client(&url).await;
    client
        .batch_execute(MIGRATIONS_0001)
        .await
        .expect("apply migrations/0001_init.sql once");
    client
        .batch_execute(MIGRATIONS_0002)
        .await
        .expect("apply migrations/0002_fragment_promotion_send_claims.sql the first time");
    client.batch_execute(MIGRATIONS_0002).await.expect(
        "re-applying migrations/0002_fragment_promotion_send_claims.sql to an \
             already-migrated database must not error -- Postgres has no \
             `ADD CONSTRAINT IF NOT EXISTS`, so this is the property a straight `ADD CONSTRAINT` \
             could silently lose",
    );
    drop(client);
    drop_throwaway_database(&admin_url, &db_name).await;
}

/// Applying the additive migration series must advance the stored revision to
/// the exact runtime version. Catalog parity alone cannot detect a stale row
/// value that would leave an otherwise migrated cell unable to enable routing.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_cell_migrated_from_0001_alone_reaches_the_schema_version_the_readiness_gate_requires() {
    let admin_url = pg_url();
    let (db_name, url) = create_throwaway_database(&admin_url, "migrationseriesversion").await;
    let client = pg_client(&url).await;
    client
        .batch_execute(MIGRATIONS_0001)
        .await
        .expect("apply migrations/0001_init.sql alone, as an out-of-band-provisioned cell has");
    let after_0001: i64 = client
        .query_one(
            "SELECT schema_version FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read schema_version after 0001 alone")
        .get(0);
    assert_eq!(
        after_0001,
        fragment_schema::FRAGMENT_SCHEMA_BASE_VERSION,
        "a cell that has run only 0001_init.sql must be at the base revision -- DECISION 3 left \
         this file unmodified"
    );

    client
        .batch_execute(MIGRATIONS_0002)
        .await
        .expect("apply migrations/0002_fragment_promotion_send_claims.sql to raise it");
    client
        .batch_execute(MIGRATIONS_0003)
        .await
        .expect("apply stage custody migration");
    client
        .batch_execute(MIGRATIONS_0004)
        .await
        .expect("apply stage policy rotation migration");
    let after_series: i64 = client
        .query_one(
            "SELECT schema_version FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read schema_version after the migration series")
        .get(0);
    assert_eq!(
        after_series,
        fragment_schema::FRAGMENT_SCHEMA_VERSION,
        "a cell migrated from 0001 through 0004 must end at the schema_version \
         ready_for_lifecycle's clean-init arm requires ({}), or every such cell enables lifecycle \
         routing never again",
        fragment_schema::FRAGMENT_SCHEMA_VERSION
    );

    drop(client);
    drop_throwaway_database(&admin_url, &db_name).await;
}
