// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Integration tests for the domain operation receipt state machine
//! (`lore-postgres/src/domain/receipts.rs`): `prepare`, `consume`,
//! `commit_terminal`, and `receipt_get`. These are the admission gate for
//! every governed mutation.
//!
//! `receipts.rs`'s own `#[cfg(test)]` module already covers the pure
//! `classify`/`uuid_v7_timestamp` boundary math offline. What's tested here is
//! the async, database-backed state machine built on top of it: which rows
//! get written for each temporal class, retry/mismatch semantics, single-use
//! consumption, hard-TTL expiry, and terminal immutability.
//!
//! Gated on `LORE_TEST_PG_URL`. The receipt cases return quietly when it is
//! unset; the `online_bootstrap_*` cases panic on it instead, because a bounded
//! DDL case that returned would be reported `passed` having proved nothing.
//! Isolated per test by a
//! random `(verified_issuer, tenant_scope_key)` pair, since the future-reject
//! quota is namespaced by exactly that tuple and must not leak between tests.

use std::time::Duration;
use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::domain::receipts::AttemptReceipt;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::ConsumeResult;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PREPARED_HARD_TTL_EXPIRED_V1;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_postgres::domain::receipts::UUID_FUTURE_HORIZON_EXCEEDED_V1;
use lore_postgres::domain::receipts::UUID_TIME_OUT_OF_RANGE_V1;
use lore_postgres::domain::receipts::admission_clock;
use lore_postgres::domain::receipts::commit_terminal;
use lore_postgres::domain::receipts::consume;
use lore_postgres::domain::receipts::prepare;
use lore_postgres::domain::receipts::receipt_get;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use tokio_postgres::Transaction;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

#[test]
fn stale_clock_predicate_distinguishes_equality_from_one_millisecond_later() {
    use lore_postgres::domain::receipts::TemporalClass;
    use lore_postgres::domain::receipts::classify;

    let clock = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let uuid_time = clock - Duration::from_secs(365 * 24 * 60 * 60);
    assert_eq!(classify(uuid_time, clock), TemporalClass::Admissible);
    assert_eq!(
        classify(uuid_time, clock + Duration::from_millis(1)),
        TemporalClass::Stale
    );
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-receipts-live.ps1"]
async fn receipt_retention_persists_both_later_of_arms_without_shortening_policy() {
    let url = pg_url().expect("owned Postgres URL");
    let store = connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    for (uuid_time, uuid_arm_wins) in [
        (clock - Duration::from_secs(2 * 24 * 60 * 60), false),
        (clock, true),
    ] {
        let key = isolated_key(uuid_v7_at(uuid_time));
        let binding = binding("lore.domain.v1.test/RetentionFormula");
        let PrepareResult::Prepared { token, .. } = store
            .domain_operation_prepare(&key, &binding, None, None)
            .await
            .unwrap()
        else {
            panic!("in-window retention fixture must prepare");
        };
        let tx = client.transaction().await.unwrap();
        let ConsumeResult::Admitted(admission) =
            consume(&tx, &key, &binding, &token).await.unwrap()
        else {
            panic!("owned prepared receipt must admit");
        };
        commit_terminal(
            &tx,
            &key,
            &DomainOutcome::Applied,
            None,
            admission.admission_clock,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let row = client.query_one(
            "SELECT full_result_expires_at=committed_at+interval '30 days', \
             compact_expires_at=GREATEST(committed_at+interval '365 days',uuid_timestamp+interval '366 days'), \
             compact_expires_at >= committed_at+interval '365 days', \
             compact_expires_at >= uuid_timestamp+interval '366 days', \
             uuid_timestamp+interval '366 days' > committed_at+interval '365 days' \
             FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 \
             AND tenant_scope_key=$3 AND operation_id=$4",
            &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &key.operation_id.as_bytes().as_slice()],
        ).await.unwrap();
        for column in 0..4 {
            assert!(
                row.get::<_, bool>(column),
                "retention formula column {column}, uuid_arm_wins={uuid_arm_wins}"
            );
        }
        assert_eq!(
            row.get::<_, bool>(4),
            uuid_arm_wins,
            "both distinct blockers must win in one fixture each"
        );
    }
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-receipts-live.ps1"]
async fn future_marker_retention_persists_uuid_arrival_plus_full_safety_horizon() {
    let url = pg_url().expect("owned Postgres URL");
    let store = connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock + Duration::from_secs(25 * 60 * 60)));
    let result = store
        .domain_operation_prepare(
            &key,
            &binding("lore.domain.v1.test/FutureRetention"),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        result,
        PrepareResult::Committed(DomainOutcome::NotApplied { .. })
    ));
    let row = client.query_one(
        "SELECT prune_after=GREATEST(rejected_at+interval '365 days',uuid_timestamp+interval '366 days'), \
         prune_after > rejected_at+interval '365 days', prune_after=uuid_timestamp+interval '366 days' \
         FROM lore_domain_operation_future_rejections WHERE verified_issuer=$1 AND authenticated_subject=$2 \
         AND tenant_scope_key=$3 AND operation_id=$4",
        &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &key.operation_id.as_bytes().as_slice()],
    ).await.unwrap();
    for column in 0..3 {
        assert!(row.get::<_, bool>(column));
    }
    assert_eq!(receipt_row_count(&client, &key).await, 0);
}

async fn connect_domain_store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap overlap"]
async fn online_bootstrap_completes_while_receipt_writer_keeps_its_transaction_open() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let _initial = connect_domain_store(&url).await;
    let mut writer = bounded_receipt_client(&url).await;
    let tx = writer
        .transaction()
        .await
        .expect("receipt writer transaction");
    // The old bootstrap retained an index's ShareLock while waiting for
    // AccessExclusiveLock here. Receipt admission then needed RowExclusiveLock.
    tx.query(
        "SELECT 1 FROM lore_domain_operation_receipts WHERE false FOR UPDATE",
        &[],
    )
    .await
    .expect("hold receipt RowShareLock until reconnect has completed");
    let key = isolated_key(uuid_v7_at(admission_clock(&tx).await.expect("clock")));
    let intent = binding("lore.domain.v1.test/OnlineBootstrap");
    let reconnect_started = std::time::Instant::now();
    let (reconnected, prepared) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            connect_domain_store(&url),
            prepare(&tx, &key, &intent, None, None)
        )
    })
    .await
    .expect(
        "reconnect and receipt admission must complete while the writer transaction stays open",
    );
    println!(
        "real reconnect and concurrent receipt admission completed with writer transaction held: {:?}",
        reconnect_started.elapsed()
    );
    let PrepareResult::Prepared { token, .. } =
        prepared.expect("writer admission concurrent with reconnect")
    else {
        panic!("expected Prepared");
    };
    tx.commit().await.expect("commit admission");
    let tx = writer.transaction().await.expect("consume transaction");
    let ConsumeResult::Admitted(admission) = consume(&tx, &key, &intent, &token)
        .await
        .expect("consume after reconnect")
    else {
        panic!("expected Admitted");
    };
    commit_terminal(
        &tx,
        &key,
        &DomainOutcome::Applied,
        None,
        admission.admission_clock,
    )
    .await
    .expect("terminal receipt after reconnect");
    tx.commit().await.expect("commit terminal receipt");
    assert!(matches!(
        reconnected
            .domain_operation_receipt_get(&key, &intent)
            .await
            .expect("durable readback"),
        ReceiptLookup::Committed {
            outcome: DomainOutcome::Applied,
            ..
        }
    ));
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap lock budget"]
async fn online_bootstrap_releases_previous_ddl_before_a_blocked_statement() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let observer = bounded_receipt_client(&url).await;
    let mut holder = bounded_receipt_client(&url).await;
    let suffix = format!("{:016x}", rand::random::<u64>());
    let first = format!("receipt_bootstrap_first_{suffix}");
    let second = format!("receipt_bootstrap_second_{suffix}");
    observer
        .batch_execute(&format!(
            "CREATE TABLE {first} (id integer); CREATE TABLE {second} (id integer)"
        ))
        .await
        .expect("create isolated DDL fixture");
    let holder_pid = receipt_backend_pid(&holder).await;
    let tx = holder.transaction().await.expect("DDL blocker transaction");
    tx.query(&format!("SELECT id FROM {second} FOR UPDATE"), &[])
        .await
        .expect("hold second relation RowShareLock");
    let pool =
        lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("bootstrap pool");
    let ddl = format!(
        "ALTER TABLE {first} ADD COLUMN IF NOT EXISTS added integer; \
         ALTER TABLE {second} ADD COLUMN IF NOT EXISTS added integer;"
    );
    let (result, blocked_at) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            lore_postgres::pool::ensure_schema_online(&pool, &ddl),
            async {
                loop {
                    let waiting: bool = observer.query_one(
                        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation = to_regclass($1) \
                         AND mode = 'AccessExclusiveLock' AND NOT granted \
                         AND $2 = ANY(pg_blocking_pids(pid)))",
                        &[&second, &holder_pid],
                    ).await.expect("observe exact blocked DDL relation").get(0);
                    if waiting {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                // Visibility of the new column from this connection proves the
                // preceding DDL committed before the next statement's lock wait.
                let blocked_at = std::time::Instant::now();
                observer
                    .execute(
                        &format!("INSERT INTO {first} (id, added) VALUES (1, 2)"),
                        &[],
                    )
                    .await
                    .expect("writer must not wait for the whole DDL sequence");
                println!(
                    "independent INSERT latency while next DDL was blocked: {:?}",
                    blocked_at.elapsed()
                );
                blocked_at
            }
        )
    })
    .await
    .expect("DDL failure and independent writer must be bounded");
    let error = result.expect_err("held relation must exhaust the DDL lock budget");
    assert!(
        error.contains("55P03") || error.contains("lock timeout"),
        "expected lock timeout, got {error}"
    );
    assert!(
        blocked_at.elapsed() < Duration::from_secs(2),
        "one blocked DDL must fail promptly"
    );
    println!(
        "blocked DDL refused and independent writer completed in {:?}: {error}",
        blocked_at.elapsed()
    );
    tx.rollback().await.expect("release owned blocker");
    assert_eq!(
        observer
            .query_one(&format!("SELECT added FROM {first} WHERE id = 1"), &[])
            .await
            .expect("durable independent write")
            .get::<_, i32>(0),
        2
    );
    lore_postgres::pool::ensure_schema_online(&pool, &ddl)
        .await
        .expect("resume after bounded refusal");
    observer
        .batch_execute(&format!("DROP TABLE {first}; DROP TABLE {second}"))
        .await
        .expect("remove only owned fixture relations");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap index replay"]
async fn online_bootstrap_skips_existing_index_during_an_open_write() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let mut writer = bounded_receipt_client(&url).await;
    let table = format!("receipt_bootstrap_index_{:016x}", rand::random::<u64>());
    let ddl = format!("CREATE INDEX IF NOT EXISTS {table}_idx ON {table} (id);");
    writer
        .batch_execute(&format!("CREATE TABLE {table} (id integer); {ddl}"))
        .await
        .expect("create indexed fixture");
    let tx = writer.transaction().await.expect("open writer");
    tx.execute(&format!("INSERT INTO {table} VALUES (1)"), &[])
        .await
        .expect("hold RowExclusiveLock");
    let pool = lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("pool");
    tokio::time::timeout(
        Duration::from_secs(2),
        lore_postgres::pool::ensure_schema_online(&pool, &ddl),
    )
    .await
    .expect("existing index must not wait for a writer")
    .expect("existing valid index accepted");
    tx.commit().await.expect("commit writer");
    writer
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("remove owned fixture");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap invalid index"]
async fn online_bootstrap_rejects_a_failed_concurrent_index() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let client = bounded_receipt_client(&url).await;
    let table = format!("receipt_bootstrap_invalid_{:016x}", rand::random::<u64>());
    client
        .batch_execute(&format!(
            "CREATE TABLE {table} (id integer); INSERT INTO {table} VALUES (1), (1)"
        ))
        .await
        .expect("create duplicate data");
    let failed_build = client
        .batch_execute(&format!(
            "CREATE UNIQUE INDEX CONCURRENTLY {table}_idx ON {table} (id)"
        ))
        .await
        .expect_err("duplicate values must leave a failed concurrent index");
    assert_eq!(
        failed_build.code(),
        Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
    );
    let valid: bool = client
        .query_one(
            "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)",
            &[&format!("{table}_idx")],
        )
        .await
        .expect("invalid index must actually exist")
        .get(0);
    assert!(!valid);
    let pool = lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("pool");
    let error = lore_postgres::pool::ensure_schema_online(
        &pool,
        &format!("CREATE UNIQUE INDEX IF NOT EXISTS {table}_idx ON {table} (id);"),
    )
    .await
    .expect_err("invalid index must refuse startup");
    assert!(error.contains("invalid"), "wrong refusal: {error}");
    client
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("remove owned fixture");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap index safety"]
async fn online_bootstrap_refuses_missing_index_on_populated_table() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let client = bounded_receipt_client(&url).await;
    let table = format!("receipt_bootstrap_populated_{:016x}", rand::random::<u64>());
    client
        .batch_execute(&format!(
            "CREATE TABLE {table} (id integer); INSERT INTO {table} VALUES (1)"
        ))
        .await
        .expect("create populated fixture");
    let pool = lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("pool");
    let error = lore_postgres::pool::ensure_schema_online(
        &pool,
        &format!("CREATE INDEX IF NOT EXISTS {table}_idx ON {table} (id);"),
    )
    .await
    .expect_err("populated index requires out-of-band build");
    assert!(
        error.contains("out-of-band concurrent index build"),
        "wrong refusal: {error}"
    );
    let absent: bool = client
        .query_one("SELECT to_regclass($1) IS NULL", &[&format!("{table}_idx")])
        .await
        .expect("index absence")
        .get(0);
    assert!(absent, "refusal must not build the index");
    client
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("remove owned fixture");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap SQL splitting"]
async fn online_bootstrap_preserves_quoted_semicolons_and_dollar_quoted_blocks() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let client = bounded_receipt_client(&url).await;
    let table = format!("receipt_bootstrap_quotes_{:016x}", rand::random::<u64>());
    let pool = lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("pool");
    let ddl = format!(
        r#"
        -- An outside comment; must not split the next statement.
        CREATE TABLE IF NOT EXISTS {table} (id integer, label text DEFAULT 'it''s; -- literal');
        DO $bootstrap$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '{table}_positive') THEN
                ALTER TABLE {table} ADD CONSTRAINT {table}_positive CHECK (id > 0);
            END IF;
        END
        $bootstrap$;
    "#
    );
    for _ in 0..2 {
        lore_postgres::pool::ensure_schema_online(&pool, &ddl)
            .await
            .expect("SQL splitter and guarded replay");
    }
    client
        .execute(&format!("INSERT INTO {table} (id) VALUES (1)"), &[])
        .await
        .expect("default insert");
    let label: String = client
        .query_one(&format!("SELECT label FROM {table}"), &[])
        .await
        .expect("literal readback")
        .get(0);
    assert_eq!(label, "it's; -- literal");
    let rejected = client
        .execute(&format!("INSERT INTO {table} (id) VALUES (0)"), &[])
        .await
        .expect_err("DO constraint must execute");
    assert_eq!(
        rejected.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    client
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("remove owned fixture");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap seed replay"]
async fn online_bootstrap_seed_replay_preserves_advanced_counters() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let client = bounded_receipt_client(&url).await;
    let table = format!("receipt_bootstrap_seed_{:016x}", rand::random::<u64>());
    let pool = lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("pool");
    let ddl = format!(
        "CREATE TABLE IF NOT EXISTS {table} (id integer PRIMARY KEY, counter bigint); \
        INSERT INTO {table} (id, counter) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;"
    );
    lore_postgres::pool::ensure_schema_online(&pool, &ddl)
        .await
        .expect("seed singleton");
    assert_eq!(
        client
            .execute(
                &format!("UPDATE {table} SET counter = 42 WHERE id = 1"),
                &[]
            )
            .await
            .expect("advance seeded counter"),
        1
    );
    lore_postgres::pool::ensure_schema_online(&pool, &ddl)
        .await
        .expect("replay seed");
    assert_eq!(
        client
            .query_one(&format!("SELECT counter FROM {table} WHERE id = 1"), &[])
            .await
            .expect("preserved counter")
            .get::<_, i64>(0),
        42
    );
    client
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("remove owned fixture");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap ALTER clauses"]
async fn online_bootstrap_rejects_mixed_alter_but_preserves_nested_and_quoted_commas() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let client = bounded_receipt_client(&url).await;
    let table = format!("receipt_bootstrap_alter_{:016x}", rand::random::<u64>());
    client
        .batch_execute(&format!("CREATE TABLE {table} (x integer, y integer)"))
        .await
        .expect("create existing-column fixture");
    let pool = lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("pool");
    let unsupported = format!(
        "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS x integer, ALTER COLUMN y SET NOT NULL;"
    );
    let error = lore_postgres::pool::ensure_schema_online(&pool, &unsupported)
        .await
        .expect_err("existing x must not mask the unsupported y alteration");
    assert!(error.contains("unsupported"), "wrong refusal: {error}");
    let mandatory: bool = client.query_one(
        "SELECT attnotnull FROM pg_attribute WHERE attrelid = to_regclass($1) AND attname = 'y'",
        &[&table],
    ).await.expect("unchanged nullable column").get(0);
    assert!(
        !mandatory,
        "unsupported mixed ALTER must not partly execute"
    );
    let supported = format!(
        "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS amount numeric(20,0), ADD COLUMN IF NOT EXISTS label text DEFAULT 'a,b''c';"
    );
    for _ in 0..2 {
        lore_postgres::pool::ensure_schema_online(&pool, &supported)
            .await
            .expect("top-level ADD clauses with nested commas");
    }
    client
        .execute(
            &format!("INSERT INTO {table} (amount) VALUES (12345678901234567890)"),
            &[],
        )
        .await
        .expect("numeric precision and quoted default");
    let row = client
        .query_one(&format!("SELECT amount::text, label FROM {table}"), &[])
        .await
        .expect("DDL behavior readback");
    assert_eq!(row.get::<_, String>(0), "12345678901234567890");
    assert_eq!(row.get::<_, String>(1), "a,b'c");
    client
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("remove owned fixture");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; online bootstrap atomic index check"]
async fn online_bootstrap_missing_index_refuses_an_uncommitted_writer_without_waiting() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let mut writer = bounded_receipt_client(&url).await;
    let observer = bounded_receipt_client(&url).await;
    let table = format!("receipt_bootstrap_race_{:016x}", rand::random::<u64>());
    writer
        .batch_execute(&format!("CREATE TABLE {table} (id integer)"))
        .await
        .expect("create empty index fixture");
    let tx = writer.transaction().await.expect("in-progress writer");
    tx.execute(&format!("INSERT INTO {table} VALUES (1)"), &[])
        .await
        .expect("hold RowExclusive with invisible row");
    let visible: i64 = observer
        .query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .expect("pre-lock emptiness check sees no committed rows")
        .get(0);
    assert_eq!(visible, 0);
    let pool = lore_postgres::pool::build_pool(&url, 1, &TlsConfig::default()).expect("pool");
    let ddl = format!("CREATE INDEX IF NOT EXISTS {table}_idx ON {table} (id);");
    let started = std::time::Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        lore_postgres::pool::ensure_schema_online(&pool, &ddl),
    )
    .await
    .expect("index bootstrap cannot wait indefinitely on invisible writer")
    .expect_err("NOWAIT must refuse while writer remains open");
    println!(
        "index NOWAIT refusal with uncommitted writer held: {:?}: {error}",
        started.elapsed()
    );
    assert!(
        error.contains("could not obtain lock"),
        "must refuse NOWAIT, not wait until lock_timeout: {error}"
    );
    let absent: bool = observer
        .query_one("SELECT to_regclass($1) IS NULL", &[&format!("{table}_idx")])
        .await
        .expect("no index published after NOWAIT refusal")
        .get(0);
    assert!(absent);
    tx.rollback()
        .await
        .expect("release writer without publishing row");
    lore_postgres::pool::ensure_schema_online(&pool, &ddl)
        .await
        .expect("now-empty table can build index");
    let valid: bool = observer
        .query_one(
            "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)",
            &[&format!("{table}_idx")],
        )
        .await
        .expect("successful empty-table index")
        .get(0);
    assert!(valid);
    observer
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("remove owned fixture");
}

async fn pg_client(url: &str) -> Client {
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

/// A UUIDv7 carrying exactly `ts` as its embedded timestamp, so a test can
/// place an operation ID at a precise offset from a captured admission clock
/// without sleeping.
fn uuid_v7_at(ts: SystemTime) -> Uuid {
    let since_epoch = ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("timestamp must be after the Unix epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        since_epoch.as_secs(),
        since_epoch.subsec_nanos(),
    ))
}

fn fresh_key(tenant_scope_key: Vec<u8>, operation_id: Uuid) -> ReceiptKey {
    ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp116-receipts/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp116-receipts-test".to_string(),
        tenant_scope_key,
        operation_id,
    }
}

/// A key with an independent, random tenant namespace — the right choice for
/// any test that isn't specifically exercising the shared-namespace quota,
/// since it can never collide with another test's quota state.
fn isolated_key(operation_id: Uuid) -> ReceiptKey {
    fresh_key(rand::random::<[u8; 8]>().to_vec(), operation_id)
}

/// A new operation under the exact same quota namespace
/// `(verified_issuer, authenticated_subject, tenant_scope_key)` as `base` —
/// the future-reject quota is keyed by that triple with no `operation_id`,
/// so a quota test must reuse it exactly rather than calling [`fresh_key`]
/// again, which mints an unrelated random `verified_issuer` every time.
fn same_namespace_key(base: &ReceiptKey, operation_id: Uuid) -> ReceiptKey {
    ReceiptKey {
        verified_issuer: base.verified_issuer.clone(),
        authenticated_subject: base.authenticated_subject.clone(),
        tenant_scope_key: base.tenant_scope_key.clone(),
        operation_id,
    }
}

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_string(),
        scope: rand::random::<[u8; 8]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

async fn receipt_row_count(client: &Client, key: &ReceiptKey) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_receipts
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("count receipt rows")
        .get(0)
}

async fn future_rejection_row_count(client: &Client, key: &ReceiptKey) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_future_rejections
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("count future-rejection rows")
        .get(0)
}

async fn quota_counts(client: &Client, key: &ReceiptKey) -> Option<(i64, i64)> {
    client
        .query_opt(
            "SELECT retained_count, bucket_count FROM lore_domain_operation_future_reject_quotas
              WHERE verified_issuer = $1 AND authenticated_subject = $2 AND tenant_scope_key = $3",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
            ],
        )
        .await
        .expect("read quota row")
        .map(|row| (row.get(0), row.get(1)))
}

struct PersistedReceipt {
    state: i16,
    consume_token: Option<Vec<u8>>,
    outcome: Option<i16>,
    not_applied_reason: Option<String>,
}

async fn fetch_receipt(client: &Client, key: &ReceiptKey) -> PersistedReceipt {
    let row = client
        .query_one(
            "SELECT state, consume_token, outcome, not_applied_reason
               FROM lore_domain_operation_receipts
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("fetch persisted receipt row");
    PersistedReceipt {
        state: row.get("state"),
        consume_token: row.get("consume_token"),
        outcome: row.get("outcome"),
        not_applied_reason: row.get("not_applied_reason"),
    }
}

/// Force a `PREPARED` row into the past relative to its own `hard_expires_at`,
/// without sleeping, so hard-TTL expiry can be exercised deterministically.
async fn age_past_hard_ttl(client: &Client, key: &ReceiptKey) {
    client
        .execute(
            "UPDATE lore_domain_operation_receipts
                SET hard_expires_at = clock_timestamp() - interval '1 second'
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age the row past its hard TTL");
}

async fn capture_clock(client: &mut Client) -> SystemTime {
    let tx: Transaction<'_> = client.transaction().await.expect("begin clock-read tx");
    let clock = admission_clock(&tx).await.expect("read admission clock");
    tx.rollback()
        .await
        .expect("roll back the read-only clock tx");
    clock
}

// These tests attest database boundaries, not OS-process crashes or lost gRPC responses.
// A missing environment is a failure for this explicitly selected deterministic lane.
async fn bounded_receipt_client(url: &str) -> Client {
    let client = pg_client(url).await;
    client
        .batch_execute("SET statement_timeout = '15s'; SET lock_timeout = '12s'")
        .await
        .expect("bound test database work");
    client
}

async fn receipt_backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("owned backend PID")
        .get(0)
}

async fn attest_receipt_blocker(observer: &Client, waiter: i32, holder: i32) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let blocked: bool = observer
                .query_one(
                    "SELECT $2::int = ANY(pg_blocking_pids($1::int))",
                    &[&waiter, &holder],
                )
                .await
                .expect("attest exact admission blocker")
                .get(0);
            if blocked {
                break;
            }
            // Polling only observes the lock condition; elapsed time never releases the gate.
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second admission must actually block on the first");
}

#[tokio::test]
#[ignore = "requires owned live Postgres; deterministic receipt lane"]
async fn deterministic_same_attempt_admission_waits_for_the_original_token() {
    concurrent_receipt_admission(false, false).await;
}

#[tokio::test]
#[ignore = "requires owned live Postgres; deterministic receipt lane"]
async fn deterministic_changed_intent_admission_cannot_obtain_the_original_token() {
    concurrent_receipt_admission(true, false).await;
}

#[tokio::test]
#[ignore = "requires owned live Postgres; deterministic receipt lane"]
async fn deterministic_serializable_admission_loser_returns_contention_without_token() {
    concurrent_receipt_admission(false, true).await;
}

async fn concurrent_receipt_admission(change_intent: bool, serializable: bool) {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let _store = connect_domain_store(&url).await;
    let mut first = bounded_receipt_client(&url).await;
    let mut second = bounded_receipt_client(&url).await;
    let observer = bounded_receipt_client(&url).await;
    let first_pid = receipt_backend_pid(&first).await;
    let second_pid = receipt_backend_pid(&second).await;
    let key = isolated_key(uuid_v7_at(capture_clock(&mut first).await));
    let intent = binding("lore.domain.v1.test/ConcurrentAdmission");
    let mut competing_intent = intent.clone();
    if change_intent {
        competing_intent.canonical_intent_digest[0] ^= 0xff;
    }
    let tx = first
        .transaction()
        .await
        .expect("first admission transaction");
    let original = prepare(&tx, &key, &intent, None, None)
        .await
        .expect("first admission");
    assert!(matches!(original, PrepareResult::Prepared { .. }));
    let (retry, ()) = tokio::join!(
        async {
            let retry_tx = second
                .build_transaction()
                .isolation_level(if serializable {
                    tokio_postgres::IsolationLevel::Serializable
                } else {
                    tokio_postgres::IsolationLevel::ReadCommitted
                })
                .start()
                .await
                .expect("second admission transaction");
            let result = prepare(&retry_tx, &key, &competing_intent, None, None).await;
            if serializable {
                retry_tx
                    .rollback()
                    .await
                    .expect("roll back strict-isolation loser");
            } else {
                retry_tx.commit().await.expect("commit concurrent retry");
            }
            result
        },
        async {
            attest_receipt_blocker(&observer, second_pid, first_pid).await;
            assert_eq!(
                receipt_row_count(&observer, &key).await,
                0,
                "uncommitted admission is invisible"
            );
            tx.commit()
                .await
                .expect("release original admission only after overlap is proven");
        }
    );
    if serializable {
        assert!(
            matches!(retry, Err(DomainError::Contention(_))),
            "strict-isolation loser must refuse without a token: {retry:?}"
        );
    } else if change_intent {
        assert_eq!(
            retry.expect("changed-intent retry"),
            PrepareResult::Mismatch,
            "changed intent must never receive a token"
        );
    } else {
        assert_eq!(
            retry.expect("exact concurrent retry"),
            original,
            "same token and expiry, not a second admission"
        );
    }
    assert_eq!(receipt_row_count(&observer, &key).await, 1);
    let PrepareResult::Prepared { token, .. } = original else {
        unreachable!()
    };
    assert_eq!(
        fetch_receipt(&observer, &key).await.consume_token,
        Some(token.to_vec())
    );
}

async fn stage_receipt_and_event(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    intent: &OperationBinding,
    token: &[u8; 32],
    cell: &str,
) -> Uuid {
    let ConsumeResult::Admitted(admission) = consume(tx, key, intent, token)
        .await
        .expect("consume owned attempt")
    else {
        panic!("owned fresh attempt must be admitted");
    };
    let version = AggregateVersion::ordinal_only(1).encode();
    let event = OutboxEvent {
        cell_id: cell,
        repository_id: key.operation_id.as_bytes(),
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id: key.operation_id.as_bytes(),
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(tx, &event)
        .await
        .expect("append same-transaction event");
    assert!(appended.created);
    commit_terminal(
        tx,
        key,
        &DomainOutcome::Applied,
        None,
        admission.admission_clock,
    )
    .await
    .expect("stage Applied receipt");
    appended.event_id
}

async fn owned_event_ids(observer: &Client, cell: &str) -> Vec<Uuid> {
    observer
        .query(
            "SELECT event_id FROM lore_outbox_events WHERE cell_id = $1",
            &[&cell],
        )
        .await
        .expect("read only owned events")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
#[ignore = "requires owned live Postgres with backend termination privilege"]
async fn deterministic_precommit_disconnect_keeps_prepared_and_no_event() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let store = connect_domain_store(&url).await;
    let mut writer = bounded_receipt_client(&url).await;
    let observer = bounded_receipt_client(&url).await;
    let pid = receipt_backend_pid(&writer).await;
    let key = isolated_key(uuid_v7_at(capture_clock(&mut writer).await));
    let intent = binding("lore.domain.v1.test/InterruptedBeforeCommit");
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &intent, None, None)
        .await
        .expect("durable admission")
    else {
        panic!("expected Prepared");
    };
    let cell = format!("receipt-precommit-{}", key.operation_id);
    let tx = writer.transaction().await.expect("mutation transaction");
    stage_receipt_and_event(&tx, &key, &intent, &token, &cell).await;
    assert!(
        owned_event_ids(&observer, &cell).await.is_empty(),
        "event cannot escape before COMMIT"
    );
    let terminated: bool = observer
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .expect("terminate only owned writer backend")
        .get(0);
    assert!(terminated, "interruption must actually occur");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let alive: bool = observer
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)",
                    &[&pid],
                )
                .await
                .expect("attest owned writer termination")
                .get(0);
            if !alive {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owned writer must exit before any COMMIT attempt");
    assert!(
        tx.commit().await.is_err(),
        "terminated writer cannot acknowledge COMMIT"
    );
    assert!(matches!(
        store
            .domain_operation_receipt_get(&key, &intent)
            .await
            .expect("independent receipt lookup"),
        ReceiptLookup::Prepared { .. }
    ));
    let retained = fetch_receipt(&observer, &key).await;
    assert_eq!(retained.state, 0);
    assert_eq!(retained.outcome, None);
    assert_eq!(retained.consume_token.as_deref(), Some(token.as_slice()));
    assert!(owned_event_ids(&observer, &cell).await.is_empty());
}

#[tokio::test]
#[ignore = "requires owned live Postgres; deterministic receipt lane"]
async fn deterministic_postcommit_disconnect_reads_original_receipt_and_event_without_replay() {
    let url = pg_url().expect("LORE_TEST_PG_URL is required");
    let store = connect_domain_store(&url).await;
    let mut writer = bounded_receipt_client(&url).await;
    let key = isolated_key(uuid_v7_at(capture_clock(&mut writer).await));
    let intent = binding("lore.domain.v1.test/InterruptedAfterCommit");
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &intent, None, None)
        .await
        .expect("durable admission")
    else {
        panic!("expected Prepared");
    };
    let cell = format!("receipt-postcommit-{}", key.operation_id);
    let tx = writer.transaction().await.expect("mutation transaction");
    let original_event = stage_receipt_and_event(&tx, &key, &intent, &token, &cell).await;
    tx.commit()
        .await
        .expect("actual commit before producer is discarded");
    // Discard producer state after a confirmed DB commit. This models an unavailable producer,
    // not transport acknowledgement loss; recovery below makes exclusively read-only calls.
    drop(writer);
    drop(store);
    let recovered = connect_domain_store(&url).await;
    let observer = bounded_receipt_client(&url).await;
    for _ in 0..2 {
        assert_eq!(
            recovered
                .domain_operation_receipt_get(&key, &intent)
                .await
                .expect("read original receipt without replay"),
            ReceiptLookup::Committed {
                outcome: DomainOutcome::Applied,
                from_future_marker: false
            }
        );
        assert_eq!(
            owned_event_ids(&observer, &cell).await,
            vec![original_event]
        );
    }
    assert_eq!(receipt_row_count(&observer, &key).await, 1);
    let mut wrong = key.clone();
    wrong.authenticated_subject.push_str("-unrelated");
    assert_eq!(
        recovered
            .domain_operation_receipt_get(&wrong, &intent)
            .await
            .expect("unrelated principal lookup"),
        ReceiptLookup::NotFound
    );
}

// ─── PostgresDomainStore wrapper seam ───────────────────────────────────────

/// The coordinator wrapper must expose the same authoritative database clock
/// used by receipt admission, bounded by samples from an independent
/// connection rather than the process clock.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn coordinator_clock_get_samples_the_database_clock() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping coordinator clock test");
        return;
    };
    let store = connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;

    let before = capture_clock(&mut client).await;
    let sampled = store
        .domain_operation_clock_get()
        .await
        .expect("coordinator clock sample");
    let after = capture_clock(&mut client).await;

    assert!(
        before <= sampled && sampled <= after,
        "coordinator sample {sampled:?} must be bounded by independent DB samples {before:?}..={after:?}"
    );
}

/// Exercise prepare and lookup through the public coordinator trait, not the
/// lower-level receipt functions used by the rest of this suite. A successful
/// wrapper commit must be visible on a separate connection, exact prepare
/// replay must return the original token, and a changed binding must remain a
/// nonmutating mismatch.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn coordinator_prepare_commit_is_visible_and_receipt_get_replays_it() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping coordinator receipt wrapper test");
        return;
    };
    let store = connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let original = binding("lore.domain.v1.test/CoordinatorWrapper");

    let first = store
        .domain_operation_prepare(&key, &original, None, None)
        .await
        .expect("coordinator prepare");
    let PrepareResult::Prepared {
        token: first_token,
        hard_expires_at: first_expiry,
    } = first
    else {
        panic!("expected Prepared, got {first:?}");
    };

    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 0, "separate connection sees PREPARED");
    assert_eq!(
        persisted.consume_token.as_deref(),
        Some(first_token.as_slice()),
        "separate connection sees the committed token"
    );

    let lookup = store
        .domain_operation_receipt_get(&key, &original)
        .await
        .expect("coordinator receipt lookup");
    let ReceiptLookup::Prepared {
        prepared_at,
        hard_expires_at,
    } = lookup
    else {
        panic!("expected Prepared lookup, got {lookup:?}");
    };
    assert!(prepared_at <= hard_expires_at);
    assert_eq!(hard_expires_at, first_expiry);

    let retry = store
        .domain_operation_prepare(&key, &original, None, None)
        .await
        .expect("exact coordinator prepare retry");
    assert!(matches!(
        retry,
        PrepareResult::Prepared { token, .. } if token == first_token
    ));

    let mut changed = original.clone();
    changed.fingerprint[0] ^= 0xFF;
    let mismatch = store
        .domain_operation_prepare(&key, &changed, None, None)
        .await
        .expect("mismatched coordinator prepare");
    assert_eq!(mismatch, PrepareResult::Mismatch);
    let unchanged = fetch_receipt(&client, &key).await;
    assert_eq!(unchanged.consume_token, persisted.consume_token);
}

/// A released client's prepare persists the `client_attempt_id` it sent
/// (`9a6d5e0`/`afaf928`), and
/// [`DomainTransactionStore::domain_operation_attempt_receipt_get`] finds the
/// resulting receipt by `(verified_issuer, authenticated_subject,
/// client_attempt_id)` alone. A caller presenting the same attempt id under a
/// different authenticated subject (the same issuer) must get `NotFound`,
/// identical to a caller quoting an id that was never prepared -- the
/// principal is the whole of the access control
/// (`receipts::attempt_receipt_get`'s own doc comment).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn attempt_receipt_get_finds_a_persisted_client_attempt_id_only_under_its_own_subject() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping attempt-receipt lookup test");
        return;
    };
    let store = connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let original = binding("lore.domain.v1.test/AttemptReceiptLookup");
    let attempt_id = Uuid::new_v4();

    let prepared = store
        .domain_operation_prepare(&key, &original, None, Some(attempt_id))
        .await
        .expect("prepare with a client attempt id");
    assert!(
        matches!(prepared, PrepareResult::Prepared { .. }),
        "expected Prepared, got {prepared:?}"
    );

    let persisted_attempt_id: Vec<u8> = client
        .query_one(
            "SELECT client_attempt_id FROM lore_domain_operation_receipts
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("fetch the persisted client_attempt_id")
        .get(0);
    assert_eq!(
        persisted_attempt_id,
        attempt_id.as_bytes().as_slice(),
        "the exact bytes the client sent must be what is stored, not re-derived"
    );

    let found = store
        .domain_operation_attempt_receipt_get(
            &key.verified_issuer,
            &key.authenticated_subject,
            &attempt_id,
        )
        .await
        .expect("attempt receipt lookup under the owning subject");
    assert_eq!(
        found.method.as_deref(),
        Some(original.method.as_str()),
        "the method the receipt was filed under must come back"
    );
    assert!(
        matches!(found.lookup, ReceiptLookup::Prepared { .. }),
        "expected Prepared, got {:?}",
        found.lookup
    );

    let wrong_subject = store
        .domain_operation_attempt_receipt_get(
            &key.verified_issuer,
            "svc:a-different-subject-entirely",
            &attempt_id,
        )
        .await
        .expect("attempt receipt lookup under a different subject");
    assert_eq!(
        wrong_subject,
        AttemptReceipt {
            acquired_locks: Vec::new(),
            lookup: ReceiptLookup::NotFound,
            method: None,
        },
        "the same attempt id under a different subject must not be found"
    );
}

// ─── the five temporal classes ──────────────────────────────────────────────

/// A stale UUID (older than the 365-day horizon) must be non-attributive:
/// `ExpiredOrUnknown`, with no row of any kind — not a receipt, not a future
/// marker, not a quota allocation.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_stale_is_expired_or_unknown_and_writes_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping stale-prepare test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock - Duration::from_secs(366 * 24 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/Stale");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(result, PrepareResult::ExpiredOrUnknown);
    assert_eq!(receipt_row_count(&client, &key).await, 0, "no receipt row");
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        0,
        "no future-rejection marker"
    );
    assert!(
        quota_counts(&client, &key).await.is_none(),
        "no quota row allocated for a stale, non-attributive attempt"
    );
}

/// An admissible UUID must prepare and persist a `PREPARED` row carrying the
/// returned consume token and expiry.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_admissible_persists_a_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping admissible-prepare test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/Admissible");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    let PrepareResult::Prepared { token, .. } = result else {
        panic!("expected Prepared, got {result:?}");
    };
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 0, "state must be PREPARED");
    assert_eq!(persisted.consume_token.as_deref(), Some(token.as_slice()));
    assert!(persisted.outcome.is_none());
}

/// A receipt-bearing future UUID must commit a real, attributable `NOT_APPLIED`
/// receipt with no domain mutation — a real row, not a compact marker.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_receipt_bearing_future_commits_a_real_not_applied_receipt() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt-bearing-future test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(6 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/ReceiptBearingFuture");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        result,
        PrepareResult::Committed(DomainOutcome::NotApplied {
            reason_version: 1,
            reason: UUID_TIME_OUT_OF_RANGE_V1.to_string(),
        })
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 1, "state must be COMMITTED");
    assert_eq!(persisted.outcome, Some(1), "outcome must be NOT_APPLIED");
    assert_eq!(
        persisted.not_applied_reason.as_deref(),
        Some(UUID_TIME_OUT_OF_RANGE_V1)
    );
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        0,
        "a receipt-bearing future rejection is an ordinary receipt, not a compact marker"
    );
}

/// A beyond-horizon UUID must create a compact future-rejection marker and
/// bump its namespace quota, with no ordinary receipt row at all.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_beyond_horizon_creates_a_compact_marker_and_no_ordinary_receipt() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping beyond-horizon test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/BeyondHorizon");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        result,
        PrepareResult::Committed(DomainOutcome::NotApplied {
            reason_version: 1,
            reason: UUID_FUTURE_HORIZON_EXCEEDED_V1.to_string(),
        })
    );
    assert_eq!(
        receipt_row_count(&client, &key).await,
        0,
        "no ordinary receipt row"
    );
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        1,
        "exactly one marker"
    );
    let (retained, bucket) = quota_counts(&client, &key)
        .await
        .expect("quota row must exist");
    assert_eq!((retained, bucket), (1, 1), "quota bumped by exactly one");
}

// ─── exact retry and mismatch ────────────────────────────────────────────────

/// An exact retry (identical key and binding) must return the same token as
/// the original `Prepared` result rather than minting a new one.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_exact_retry_returns_the_same_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping exact-retry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/ExactRetry");

    let tx = client.transaction().await.expect("begin first tx");
    let first = prepare(&tx, &key, &b, None, None)
        .await
        .expect("first prepare");
    tx.commit().await.expect("commit first");
    let PrepareResult::Prepared {
        token: first_token, ..
    } = first
    else {
        panic!("expected Prepared, got {first:?}");
    };

    let tx = client.transaction().await.expect("begin retry tx");
    let retry = prepare(&tx, &key, &b, None, None)
        .await
        .expect("retry prepare");
    tx.commit().await.expect("commit retry");
    let PrepareResult::Prepared {
        token: retry_token, ..
    } = retry
    else {
        panic!("expected Prepared on retry, got {retry:?}");
    };

    assert_eq!(
        first_token, retry_token,
        "an exact retry must return the original token"
    );
}

/// A retry that changes exactly one of method/scope/fingerprint_version/
/// fingerprint must return `Mismatch` and must not touch the stored row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_retry_with_a_changed_binding_field_returns_mismatch_and_mutates_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping binding-mismatch test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;

    for field in ["method", "scope", "fingerprint_version", "fingerprint"] {
        let clock = capture_clock(&mut client).await;
        let key = isolated_key(uuid_v7_at(clock));
        let original = binding("lore.domain.v1.test/MismatchOriginal");

        let tx = client.transaction().await.expect("begin original tx");
        let first = prepare(&tx, &key, &original, None, None)
            .await
            .expect("original prepare");
        tx.commit().await.expect("commit original");
        let PrepareResult::Prepared {
            token: original_token,
            ..
        } = first
        else {
            panic!("expected Prepared, got {first:?}");
        };

        let mut changed = original.clone();
        match field {
            "method" => changed.method.push_str("-changed"),
            "scope" => changed.scope[0] ^= 0xFF,
            "fingerprint_version" => changed.fingerprint_version += 1,
            "fingerprint" => changed.fingerprint[0] ^= 0xFF,
            _ => unreachable!(),
        }

        let tx = client.transaction().await.expect("begin mismatch tx");
        let result = prepare(&tx, &key, &changed, None, None)
            .await
            .expect("mismatched prepare must not error");
        tx.commit().await.expect("commit mismatch attempt");

        assert_eq!(
            result,
            PrepareResult::Mismatch,
            "changed {field} must return Mismatch"
        );
        let persisted = fetch_receipt(&client, &key).await;
        assert_eq!(persisted.state, 0, "row must remain PREPARED for {field}");
        assert_eq!(
            persisted.consume_token.as_deref(),
            Some(original_token.as_slice()),
            "the original token must be untouched for {field}"
        );
    }
}

// ─── consume ─────────────────────────────────────────────────────────────────

/// Once a mutation transaction consumes and commits a receipt, the row is
/// terminal — a later `consume` with the same token must return `None`
/// because the row is no longer `PREPARED`, not because the token itself
/// stops matching.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_is_single_use_once_the_receipt_is_terminal() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping single-use consume test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/ConsumeSingleUse");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key, &b, None, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };

    let tx = client.transaction().await.expect("begin consume+commit tx");
    let admission = consume(&tx, &key, &b, &token)
        .await
        .expect("consume must not error");
    let ConsumeResult::Admitted(admission) = admission else {
        panic!("first consume must admit");
    };
    commit_terminal(
        &tx,
        &key,
        &DomainOutcome::Applied,
        None,
        admission.admission_clock,
    )
    .await
    .expect("commit_terminal");
    tx.commit().await.expect("commit the mutation transaction");

    let tx = client.transaction().await.expect("begin second consume tx");
    let second = consume(&tx, &key, &b, &token)
        .await
        .expect("second consume must not error");
    tx.rollback()
        .await
        .expect("roll back read-only second attempt");

    assert!(
        matches!(
            second,
            ConsumeResult::Committed {
                outcome: DomainOutcome::Applied,
                ..
            }
        ),
        "consume must replay the committed outcome once the receipt is terminal"
    );
}

/// A token is scoped to its exact key and binding: presenting it against a
/// different key, or the right key with a different binding, must return
/// `None` in every case, never distinguishing which part mismatched.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_rejects_a_token_presented_for_the_wrong_key_or_binding() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping wrong-key/binding consume test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key_a = isolated_key(uuid_v7_at(clock));
    let binding_a = binding("lore.domain.v1.test/ConsumeScopeA");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key_a, &binding_a, None, None)
        .await
        .expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };

    // Wrong key entirely (a key that was never prepared).
    let key_b = isolated_key(uuid_v7_at(clock));
    let tx = client.transaction().await.expect("begin wrong-key tx");
    let result = consume(&tx, &key_b, &binding_a, &token)
        .await
        .expect("consume must not error");
    tx.rollback().await.expect("rollback");
    assert!(
        matches!(result, ConsumeResult::Rejected),
        "a token for key_a must not consume against key_b"
    );

    // Right key, wrong binding.
    let wrong_binding = binding("lore.domain.v1.test/ConsumeScopeWrong");
    let tx = client.transaction().await.expect("begin wrong-binding tx");
    let result = consume(&tx, &key_a, &wrong_binding, &token)
        .await
        .expect("consume must not error");
    tx.rollback().await.expect("rollback");
    assert!(
        matches!(result, ConsumeResult::Rejected),
        "the right key with the wrong binding must not consume"
    );

    // Right key and binding, wrong token.
    let mut wrong_token = token;
    wrong_token[0] ^= 0xFF;
    let tx = client.transaction().await.expect("begin wrong-token tx");
    let result = consume(&tx, &key_a, &binding_a, &wrong_token)
        .await
        .expect("consume must not error");
    tx.rollback().await.expect("rollback");
    assert!(
        matches!(result, ConsumeResult::Rejected),
        "the right key and binding with the wrong token must not consume"
    );

    // Sanity: the original token against the original key/binding still works.
    let tx = client.transaction().await.expect("begin correct tx");
    let result = consume(&tx, &key_a, &binding_a, &token)
        .await
        .expect("consume must not error");
    tx.rollback()
        .await
        .expect("rollback (do not actually terminalize)");
    assert!(
        matches!(result, ConsumeResult::Admitted(_)),
        "the original token/key/binding combination must still consume"
    );
}

/// The canonical intent digest is part of the immutable operation binding.
/// A caller that changes only this field must not read or consume the prepared
/// row, and the failed attempts must leave the original token usable.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_and_receipt_get_reject_changed_canonical_intent() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping canonical-intent binding test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let original = binding("lore.domain.v1.test/CanonicalIntent");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key, &original, None, None)
        .await
        .expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };

    let mut changed = original.clone();
    changed.canonical_intent_digest[0] ^= 0xff;

    let tx = client
        .transaction()
        .await
        .expect("begin mismatched lookup tx");
    let lookup = receipt_get(&tx, &key, &changed)
        .await
        .expect("mismatched lookup must not error");
    tx.rollback().await.expect("rollback lookup");
    assert_eq!(
        lookup,
        ReceiptLookup::Mismatch,
        "changed canonical intent must not read the prepared receipt"
    );

    let tx = client
        .transaction()
        .await
        .expect("begin mismatched consume tx");
    let consumed = consume(&tx, &key, &changed, &token)
        .await
        .expect("mismatched consume must not error");
    tx.rollback().await.expect("rollback mismatched consume");
    assert!(
        matches!(consumed, ConsumeResult::Rejected),
        "changed canonical intent must not consume the prepared receipt"
    );

    let tx = client
        .transaction()
        .await
        .expect("begin exact consume control tx");
    let exact = consume(&tx, &key, &original, &token)
        .await
        .expect("exact consume must not error");
    tx.rollback().await.expect("rollback exact consume control");
    assert!(
        matches!(exact, ConsumeResult::Admitted(_)),
        "mismatched lookup and consume must leave the original token usable"
    );
}

// ─── hard-TTL expiry ─────────────────────────────────────────────────────────

/// `prepare` against a row already past its hard TTL must terminalize it to
/// `NOT_APPLIED(PREPARED_HARD_TTL_EXPIRED_V1)` rather than returning stale
/// `Prepared` state or minting a second row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_expires_a_past_ttl_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping prepare-driven TTL expiry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/PrepareExpiry");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    age_past_hard_ttl(&client, &key).await;

    let tx = client.transaction().await.expect("begin second-touch tx");
    let result = prepare(&tx, &key, &b, None, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        result,
        PrepareResult::Committed(DomainOutcome::NotApplied {
            reason_version: 1,
            reason: PREPARED_HARD_TTL_EXPIRED_V1.to_string(),
        })
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 1, "expiry must terminalize the row");
}

/// `consume` against a row already past its hard TTL must terminalize it the
/// same way and return `None`, never a live admission.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_expires_a_past_ttl_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping consume-driven TTL expiry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/ConsumeExpiry");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key, &b, None, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };
    age_past_hard_ttl(&client, &key).await;

    let tx = client.transaction().await.expect("begin consume tx");
    let result = consume(&tx, &key, &b, &token)
        .await
        .expect("consume must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        match result {
            ConsumeResult::Committed { outcome, .. } => outcome,
            _ => panic!("consume of a past-TTL row must return its committed outcome"),
        },
        DomainOutcome::NotApplied {
            reason_version: 1,
            reason: PREPARED_HARD_TTL_EXPIRED_V1.to_string(),
        }
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(
        persisted.state, 1,
        "consume-driven expiry must terminalize the row"
    );
    assert_eq!(
        persisted.not_applied_reason.as_deref(),
        Some(PREPARED_HARD_TTL_EXPIRED_V1)
    );
}

/// `receipt_get`'s own doc comment for [`PREPARED_HARD_TTL_EXPIRED_V1`]-style
/// expiry (`expire_prepared`'s comment: "Every prepare, get, and consume
/// touch performs this same transition") claims lookup also drives expiry.
/// This pins the currently-observed behavior so a fix or a contract
/// correction shows up as a diff here rather than silently.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_get_of_a_past_ttl_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt_get TTL-expiry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/GetExpiry");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    age_past_hard_ttl(&client, &key).await;

    let tx = client.transaction().await.expect("begin get tx");
    let looked_up = receipt_get(&tx, &key, &b)
        .await
        .expect("receipt_get must not error");
    tx.commit().await.expect("commit");

    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(
        (looked_up, persisted.state),
        (
            ReceiptLookup::Committed {
                outcome: DomainOutcome::NotApplied {
                    reason_version: 1,
                    reason: PREPARED_HARD_TTL_EXPIRED_V1.to_string(),
                },
                from_future_marker: false,
            },
            1
        ),
        "receipt_get is documented (expire_prepared's comment) to drive hard-TTL expiry \
         the same way prepare/consume do; if this assertion fails, receipt_get returned \
         Prepared{{..}} over the still-PREPARED row instead — receipt_get's own function body \
         never checks clock against hard_expires_at for the PREPARED branch, unlike prepare \
         and consume, so this is expected to currently FAIL as a genuine implementation gap, \
         not a test defect. Report exact vs actual to the main session rather than loosening \
         this assertion."
    );
}

// ─── terminal immutability ───────────────────────────────────────────────────

/// A terminal row is immutable: a second `commit_terminal` against an
/// already-committed row must error rather than silently overwrite it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn commit_terminal_against_an_already_committed_row_errors() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping terminal-immutability test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/TerminalImmutable");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None, None).await.expect("prepare");
    let admission_clock_value = admission_clock(&tx).await.expect("read clock");
    commit_terminal(
        &tx,
        &key,
        &DomainOutcome::Applied,
        None,
        admission_clock_value,
    )
    .await
    .expect("first commit_terminal must succeed");
    tx.commit().await.expect("commit first terminalization");

    let tx = client
        .transaction()
        .await
        .expect("begin second commit_terminal tx");
    let second_clock = admission_clock(&tx).await.expect("read clock");
    let err = commit_terminal(
        &tx,
        &key,
        &DomainOutcome::NotApplied {
            reason_version: 1,
            reason: "SHOULD_NEVER_APPLY".to_string(),
        },
        None,
        second_clock,
    )
    .await
    .expect_err("a second commit_terminal against an already-terminal row must error");
    tx.rollback()
        .await
        .expect("rollback the rejected second attempt");

    assert!(
        matches!(&err, DomainError::Internal(msg) if msg.contains("must never be rewritten")),
        "expected an Internal error naming immutability, got {err:?}"
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(
        persisted.outcome,
        Some(0),
        "the original APPLIED outcome must be untouched"
    );
}

// ─── receipt_get never returns the token ────────────────────────────────────

/// `ReceiptLookup::Prepared` structurally carries only `prepared_at` and
/// `hard_expires_at` — there is no field for the token, so a caller cannot
/// obtain it through this path even by accident. Destructuring only the
/// documented fields here is itself part of the proof: this would not
/// compile if the variant carried a third field.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_get_of_a_prepared_row_carries_no_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt_get token-shape test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/GetNoToken");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");

    let tx = client.transaction().await.expect("begin get tx");
    let looked_up = receipt_get(&tx, &key, &b)
        .await
        .expect("receipt_get must not error");
    tx.commit().await.expect("commit");

    let ReceiptLookup::Prepared {
        prepared_at: _,
        hard_expires_at: _,
    } = looked_up
    else {
        panic!("expected Prepared, got {looked_up:?}");
    };
}

// ─── future-marker binding scoping ───────────────────────────────────────────

/// A future-rejection marker created under one binding must not answer a
/// lookup made with a *different* binding — that would resolve one operation
/// with another operation's stored result, which CR-029 forbids for every
/// other receipt path. `prepare` and `receipt_get` both consult
/// `load_future_marker(tx, key)` for a hit under the same `operation_id`
/// (shared with any other caller who reuses this UUID with different
/// content), so this must fail closed exactly like the ordinary-receipt
/// mismatch path does.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_of_a_future_marker_under_a_different_binding_must_return_mismatch() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping future-marker binding-scope test (prepare)");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let binding_a = binding("lore.domain.v1.test/FutureMarkerA");

    let tx = client.transaction().await.expect("begin first tx");
    let first = prepare(&tx, &key, &binding_a, None, None)
        .await
        .expect("first prepare");
    tx.commit().await.expect("commit first");
    assert!(matches!(
        first,
        PrepareResult::Committed(DomainOutcome::NotApplied { .. })
    ));

    let binding_b = binding("lore.domain.v1.test/FutureMarkerB");
    let tx = client.transaction().await.expect("begin second tx");
    let second = prepare(&tx, &key, &binding_b, None, None)
        .await
        .expect("second prepare");
    tx.commit().await.expect("commit second");

    assert_eq!(
        second,
        PrepareResult::Mismatch,
        "a future marker under binding_a must not answer a prepare under binding_b with \
         binding_a's outcome — that would resolve one operation with another operation's \
         stored result. `load_future_marker` compares the stored method/scope/\
         fingerprint_version/fingerprint against the caller's binding and returns \
         FutureMarker::Mismatch on any difference before FutureMarker::Exact can apply."
    );
}

/// Same invariant, `receipt_get` side: a lookup under a different binding
/// must not resolve to the marker's outcome either.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_get_of_a_future_marker_under_a_different_binding_must_return_mismatch() {
    let Some(url) = pg_url() else {
        eprintln!(
            "LORE_TEST_PG_URL unset; skipping future-marker binding-scope test (receipt_get)"
        );
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let binding_a = binding("lore.domain.v1.test/FutureMarkerGetA");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &binding_a, None, None)
        .await
        .expect("prepare");
    tx.commit().await.expect("commit prepare");

    let binding_b = binding("lore.domain.v1.test/FutureMarkerGetB");
    let tx = client.transaction().await.expect("begin get tx");
    let looked_up = receipt_get(&tx, &key, &binding_b)
        .await
        .expect("receipt_get must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        looked_up,
        ReceiptLookup::Mismatch,
        "receipt_get must not resolve a future marker stored under binding_a to a lookup \
         made with binding_b; see the companion prepare-side test for the shared \
         `load_future_marker` binding check this exercises"
    );
}

// ─── future-rejection quota ──────────────────────────────────────────────────

/// At the 1,024-retained-marker limit, prepare must return `CapacityExhausted`
/// and must not write a marker for the new operation or bump the quota
/// further.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn beyond_horizon_prepare_at_retained_quota_limit_is_capacity_exhausted() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping retained-quota-limit test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let tenant_scope: Vec<u8> = rand::random::<[u8; 8]>().to_vec();
    let issuer_key = fresh_key(
        tenant_scope.clone(),
        uuid_v7_at(clock + Duration::from_secs(25 * 60 * 60)),
    );
    let b = binding("lore.domain.v1.test/QuotaRetainedSeed");

    // Seed the quota row for real via one successful marker admission.
    let tx = client.transaction().await.expect("begin seed tx");
    prepare(&tx, &issuer_key, &b, None, None)
        .await
        .expect("seed prepare");
    tx.commit().await.expect("commit seed");

    client
        .execute(
            "UPDATE lore_domain_operation_future_reject_quotas
                SET retained_count = 1024
              WHERE verified_issuer = $1 AND authenticated_subject = $2 AND tenant_scope_key = $3",
            &[
                &issuer_key.verified_issuer,
                &issuer_key.authenticated_subject,
                &tenant_scope,
            ],
        )
        .await
        .expect("force retained_count to the limit");

    let clock2 = capture_clock(&mut client).await;
    let new_operation_key = same_namespace_key(
        &issuer_key,
        uuid_v7_at(clock2 + Duration::from_secs(25 * 60 * 60)),
    );
    let tx = client.transaction().await.expect("begin exhausted tx");
    let result = prepare(
        &tx,
        &new_operation_key,
        &binding("lore.domain.v1.test/QuotaRetainedNew"),
        None,
        None,
    )
    .await
    .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(result, PrepareResult::CapacityExhausted);
    assert_eq!(
        future_rejection_row_count(&client, &new_operation_key).await,
        0,
        "no marker written for the rejected operation"
    );
    let (retained, _bucket) = quota_counts(&client, &new_operation_key)
        .await
        .expect("quota row still exists");
    assert_eq!(
        retained, 1024,
        "retained_count must not have been incremented past the limit"
    );
}

/// At the 64-per-hour limit, the same admission backpressure applies.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn beyond_horizon_prepare_at_hourly_quota_limit_is_capacity_exhausted() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping hourly-quota-limit test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let tenant_scope: Vec<u8> = rand::random::<[u8; 8]>().to_vec();
    let seed_key = fresh_key(
        tenant_scope.clone(),
        uuid_v7_at(clock + Duration::from_secs(25 * 60 * 60)),
    );

    let tx = client.transaction().await.expect("begin seed tx");
    prepare(
        &tx,
        &seed_key,
        &binding("lore.domain.v1.test/QuotaHourlySeed"),
        None,
        None,
    )
    .await
    .expect("seed prepare");
    tx.commit().await.expect("commit seed");

    client
        .execute(
            "UPDATE lore_domain_operation_future_reject_quotas
                SET bucket_count = 64
              WHERE verified_issuer = $1 AND authenticated_subject = $2 AND tenant_scope_key = $3",
            &[
                &seed_key.verified_issuer,
                &seed_key.authenticated_subject,
                &tenant_scope,
            ],
        )
        .await
        .expect("force bucket_count to the limit");

    let clock2 = capture_clock(&mut client).await;
    let new_operation_key = same_namespace_key(
        &seed_key,
        uuid_v7_at(clock2 + Duration::from_secs(25 * 60 * 60)),
    );
    let tx = client.transaction().await.expect("begin exhausted tx");
    let result = prepare(
        &tx,
        &new_operation_key,
        &binding("lore.domain.v1.test/QuotaHourlyNew"),
        None,
        None,
    )
    .await
    .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(result, PrepareResult::CapacityExhausted);
    assert_eq!(
        future_rejection_row_count(&client, &new_operation_key).await,
        0
    );
    let (_retained, bucket) = quota_counts(&client, &new_operation_key)
        .await
        .expect("quota row still exists");
    assert_eq!(
        bucket, 64,
        "bucket_count must not have been incremented past the hourly limit"
    );
}

/// `AuthorizationWitness` is accepted end to end by `prepare`: passing one
/// must not error and must not change the observable `Prepared` outcome. The
/// witness fields themselves are internal/server-only evidence, not part of
/// this public contract, so this is a smoke test of the plumbing rather than
/// a field-by-field pin.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_accepts_an_authorization_witness() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping authorization-witness test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/WithWitness");
    let witness = AuthorizationWitness {
        authorization_id: key.operation_id.as_bytes().to_vec(),
        authorization_revision: 1,
        verification_nonce: rand::random::<[u8; 32]>().to_vec(),
        bound_fields_digest: rand::random::<[u8; 32]>().to_vec(),
        consumed_ticket_sha256: rand::random::<[u8; 32]>().to_vec(),
        expected_claim_identity_digest: rand::random::<[u8; 32]>().to_vec(),
    };

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, Some(&witness), None)
        .await
        .expect("prepare with a witness must not error");
    tx.commit().await.expect("commit");

    assert!(matches!(result, PrepareResult::Prepared { .. }));
}

/// Two concurrent `prepare` calls against the identical beyond-horizon key
/// must not double-count the future-reject quota: `insert_future_marker`'s
/// `INSERT ... ON CONFLICT DO NOTHING` on the marker row means the loser's
/// insert affects zero rows, and the increment must be gated on that rather
/// than running unconditionally after every attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn concurrent_duplicate_future_marker_prepares_do_not_double_count_the_quota() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping concurrent-duplicate-marker test");
        return;
    };
    connect_domain_store(&url).await;
    let clock = capture_clock(&mut pg_client(&url).await).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/ConcurrentDuplicateMarker");

    let mut client_a = pg_client(&url).await;
    let mut client_b = pg_client(&url).await;
    let key_a = key.clone();
    let key_b = key.clone();
    let binding_a = b.clone();
    let binding_b = b.clone();

    let (result_a, result_b) = tokio::join!(
        async {
            let tx = client_a.transaction().await.expect("begin tx a");
            let r = prepare(&tx, &key_a, &binding_a, None, None)
                .await
                .expect("prepare a");
            tx.commit().await.expect("commit a");
            r
        },
        async {
            let tx = client_b.transaction().await.expect("begin tx b");
            let r = prepare(&tx, &key_b, &binding_b, None, None)
                .await
                .expect("prepare b");
            tx.commit().await.expect("commit b");
            r
        },
    );

    let expected = PrepareResult::Committed(DomainOutcome::NotApplied {
        reason_version: 1,
        reason: UUID_FUTURE_HORIZON_EXCEEDED_V1.to_string(),
    });
    assert_eq!(
        result_a, expected,
        "both concurrent callers see the same decisive outcome"
    );
    assert_eq!(result_b, expected);

    let client = pg_client(&url).await;
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        1,
        "exactly one marker row despite two concurrent attempts"
    );
    let (retained, bucket) = quota_counts(&client, &key)
        .await
        .expect("quota row must exist");
    assert_eq!(
        (retained, bucket),
        (1, 1),
        "the quota must be incremented exactly once, not once per attempt"
    );
}
