// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Live-Postgres proof for WP-115 row 80 idea 3: the fragment coordinator's
//! hot statements run through a per-connection prepared-statement cache, kept
//! on custom plans by `plan_cache_mode = force_custom_plan` on every pooled
//! connection.
//!
//! The source half is `statement_cache_source_pins.rs`; the statement
//! inventory is read from the `*_cached(` call sites by `common/cached_sql.rs`.
//!
//! Every case is `#[ignore]` and needs `LORE_TEST_PG_URL`. Run through
//! `tests/run-fragment-lifecycle-live.ps1`, which gives each case its own
//! fresh database, or with
//! `cargo test -p lore-postgres --test statement_cache_live -- --ignored`.

#[path = "common/cached_sql.rs"]
mod cached_sql;

#[path = "common/drain_candidate.rs"]
mod drain_candidate;

#[path = "common/stage_policy.rs"]
mod stage_policy;

use std::collections::BTreeSet;
use std::time::Duration;

use cached_sql::PINS;
use cached_sql::cached_sites;
use cached_sql::distinct_sites;
use cached_sql::pin_matches;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteSettlement;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_postgres::pool::verify_plan_cache_mode;
use lore_postgres::statement_cache::CachedStatements;
use lore_postgres::statement_cache::PLAN_CACHE_MODE;
use lore_postgres::statement_cache::apply_plan_cache_mode;
use lore_postgres::statement_cache::prepared_statements;
use lore_postgres::statement_cache::show_plan_cache_mode;
use tokio_postgres::Client;
use tokio_postgres::SimpleQueryMessage;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers (self-contained, mirroring `fragment_drain_candidates.rs`)
// ---------------------------------------------------------------------------

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL").expect("runner must set LORE_TEST_PG_URL")
}

async fn store(url: &str) -> PostgresDomainStore {
    let store = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
        .await
        .expect("connect domain store");
    store
        .fragment_coordinator()
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-118 fixture");
    stage_policy::initialize(url, &store.fragment_coordinator()).await;
    store
}

/// A plain connection: no pool, so no post-create hook. Its session runs with
/// the server default, which is what makes it a control.
async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

fn random_hash() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

fn legacy_key(hash: &[u8]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn manifest(object_key: &str, seed: u8, authority: EpochAuthority) -> FragmentManifest {
    FragmentManifest {
        authority,
        object_key: object_key.to_owned(),
        manifest_id: vec![seed; 32],
        size_payload: 128,
        size_content: 100,
        decoded_hash: vec![seed.wrapping_add(1); 32],
        payload_flags: 7,
    }
}

fn write_claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xA5; 32],
        1,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .expect("valid test write claim")
}

async fn stage_hash(coordinator: &PostgresFragmentCoordinator, hash: &[u8], seed: u8) {
    let BeginOutcome::Admitted(stage_intent) = coordinator
        .begin_stage(
            hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: 128,
                original_flags: 7,
            },
        )
        .await
        .expect("begin stage on a fresh hash")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "statement-cache/staged",
                    seed,
                    EpochAuthority::Staged
                )),
            )
            .await
            .expect("commit_staged against a fresh intent"),
        CommitVerdict::Published
    );
}

async fn show(client: &Client) -> String {
    show_plan_cache_mode(client)
        .await
        .expect("SHOW plan_cache_mode")
}

async fn backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("pg_backend_pid")
        .get(0)
}

// ---------------------------------------------------------------------------
// (a) every pooled connection reports force_custom_plan
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn every_pooled_connection_reports_force_custom_plan_across_recycle_and_growth() {
    let url = pg_url();
    // Control: the server's own default for a plain session. Without this the
    // assertions below could pass on a server already configured that way.
    let control = client(&url).await;
    assert_eq!(
        show(&control).await,
        "auto",
        "the disposable server must default to auto, or the pool assertions prove nothing"
    );

    let pool = build_pool(&url, 4, &TlsConfig::default()).expect("build pool");

    // One connection, then returned and taken again: a recycle, not a new connect.
    let first_pid = {
        let connection = pool.get().await.expect("first checkout");
        assert_eq!(show(&connection).await, PLAN_CACHE_MODE);
        backend_pid(&connection).await
    };
    let (recycled_pid, size_after_recycle) = {
        let connection = pool.get().await.expect("recycled checkout");
        assert_eq!(show(&connection).await, PLAN_CACHE_MODE, "after recycle");
        (backend_pid(&connection).await, pool.status().size)
    };
    assert_eq!(
        recycled_pid, first_pid,
        "the second checkout must reuse the first connection, or it proved nothing about recycle"
    );
    assert_eq!(
        size_after_recycle, 1,
        "a recycle must not open a connection"
    );

    // Grow beyond the one connection the pool had: hold all four at once.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(pool.get().await.expect("growth checkout"));
    }
    let mut pids = BTreeSet::new();
    for connection in &held {
        assert_eq!(
            show(connection).await,
            PLAN_CACHE_MODE,
            "a connection opened after the pool's first"
        );
        pids.insert(backend_pid(connection).await);
    }
    assert_eq!(
        pids.len(),
        4,
        "four held checkouts must be four connections"
    );
    assert!(pids.contains(&first_pid));
    assert_eq!(pool.status().size, 4);
    drop(held);

    // And once more after every connection has been through a return.
    let mut again = Vec::new();
    for _ in 0..4 {
        again.push(pool.get().await.expect("post-return checkout"));
    }
    for connection in &again {
        assert_eq!(show(connection).await, PLAN_CACHE_MODE, "after return");
    }
    // The pool is at its maximum while these are held; verification needs a slot.
    drop(again);
    verify_plan_cache_mode(&pool)
        .await
        .expect("verify_plan_cache_mode on a healthy pool");
}

// ---------------------------------------------------------------------------
// (d) the setting is verified and a failure is loud
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_connection_that_lost_the_setting_fails_verification_and_a_dead_session_fails_apply() {
    let url = pg_url();
    let pool = build_pool(&url, 1, &TlsConfig::default()).expect("build pool");
    verify_plan_cache_mode(&pool)
        .await
        .expect("healthy pool verifies");

    // Recycling is `Fast`: it does not reset session state, and the hook runs
    // only on creation. So a connection that loses the setting stays that way,
    // and the startup check is what catches it.
    {
        let connection = pool.get().await.expect("checkout");
        connection
            .batch_execute("SET plan_cache_mode = auto")
            .await
            .expect("drop the setting on the pooled session");
    }
    let error = verify_plan_cache_mode(&pool)
        .await
        .expect_err("a pool whose connection runs auto must fail verification");
    assert!(
        error.contains("plan_cache_mode auto") && error.contains(PLAN_CACHE_MODE),
        "the failure must name the actual and expected mode: {error}"
    );
    {
        let connection = pool.get().await.expect("checkout");
        apply_plan_cache_mode(&connection)
            .await
            .expect("apply restores the setting");
    }
    verify_plan_cache_mode(&pool)
        .await
        .expect("restored pool verifies");

    // A session the server will not talk to: apply fails with its documented
    // error rather than reporting success. (A role that merely rejects `SET`
    // is not constructible for a USERSET parameter, so a dead session stands
    // in for "the SET could not be applied".)
    let victim = client(&url).await;
    let victim_pid = backend_pid(&victim).await;
    let admin = client(&url).await;
    admin
        .execute("SELECT pg_terminate_backend($1)", &[&victim_pid])
        .await
        .expect("terminate the victim backend");
    let error = apply_plan_cache_mode(&victim)
        .await
        .expect_err("apply on a terminated session must fail");
    assert!(
        error.starts_with("postgres session plan_cache_mode:"),
        "the documented error prefix changed: {error}"
    );
}

// ---------------------------------------------------------------------------
// (c) cache correctness
// ---------------------------------------------------------------------------

const PROBE_SQL: &str =
    "SELECT hash, current_epoch, state FROM lore_fragment_lifecycle WHERE hash = $1";

async fn prepared_rows(client: &Client, sql: &str) -> Vec<(i64, i64)> {
    client
        .query(
            "SELECT custom_plans, generic_plans FROM pg_prepared_statements WHERE statement = $1",
            &[&sql],
        )
        .await
        .expect("read pg_prepared_statements")
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_cached_statement_is_prepared_once_replays_identically_and_never_goes_generic() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x41).await;

    // One connection, so every execution is on the same session's cache.
    let pool = build_pool(&url, 1, &TlsConfig::default()).expect("build pool");
    let connection = pool.get().await.expect("checkout");
    assert!(
        prepared_rows(&connection, PROBE_SQL).await.is_empty(),
        "fixture: the probe must start unprepared on this connection"
    );
    assert_eq!(connection.statement_cache.size(), 0);

    let first = connection
        .query_cached(PROBE_SQL, &[&hash])
        .await
        .expect("first cached execution");
    assert_eq!(first.len(), 1);
    let snapshot = |rows: &[tokio_postgres::Row]| {
        rows.iter()
            .map(|row| {
                (
                    row.get::<_, Vec<u8>>(0),
                    row.get::<_, i64>(1),
                    row.get::<_, i16>(2),
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = snapshot(&first);
    assert_eq!(expected[0].0, hash);

    // The first execution prepared it once, on the server and in the cache.
    assert_eq!(connection.statement_cache.size(), 1);
    assert_eq!(prepared_rows(&connection, PROBE_SQL).await.len(), 1);
    assert!(
        prepared_statements().contains(&PROBE_SQL),
        "the process-wide registry must list a statement the first time it is prepared"
    );

    // Repeat well past PostgreSQL's five-execution generic-plan threshold.
    for round in 2..=9 {
        let rows = connection
            .query_cached(PROBE_SQL, &[&hash])
            .await
            .expect("repeat cached execution");
        assert_eq!(snapshot(&rows), expected, "execution {round} differs");
        assert_eq!(
            connection.statement_cache.size(),
            1,
            "execution {round} must not prepare again"
        );
    }
    let listed = prepared_rows(&connection, PROBE_SQL).await;
    assert_eq!(
        listed.len(),
        1,
        "the statement must be listed once, not once per call"
    );
    assert_eq!(
        prepared_statements()
            .iter()
            .filter(|sql| **sql == PROBE_SQL)
            .count(),
        1
    );
    // The point of the mode: nine executions, every one planned afresh.
    assert_eq!(
        listed[0],
        (9, 0),
        "(custom_plans, generic_plans) after nine executions under force_custom_plan"
    );

    // Control: the same shape on a plain session under `auto` DOES go generic
    // after five executions. Without it, `generic_plans == 0` above could be
    // an artifact of a statement the planner never prefers generic for.
    let control = client(&url).await;
    control
        .batch_execute(&format!("PREPARE control_probe(bytea) AS {PROBE_SQL}"))
        .await
        .expect("prepare control");
    let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for _ in 0..9 {
        control
            .simple_query(&format!("EXECUTE control_probe(decode('{hex}','hex'))"))
            .await
            .expect("execute control");
    }
    let (_, generic) = prepared_rows(
        &control,
        &format!("PREPARE control_probe(bytea) AS {PROBE_SQL}"),
    )
    .await
    .first()
    .copied()
    .unwrap_or_else(|| panic!("control statement not listed"));
    assert!(
        generic > 0,
        "control: an `auto` session must switch to a generic plan within nine executions, or this \
         fixture cannot distinguish the pooled setting"
    );
}

// ---------------------------------------------------------------------------
// registry matches the call sites; a real lifecycle only prepares what is written
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_real_lifecycle_prepares_only_statements_that_are_literal_at_a_pinned_call_site() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();

    // Stage, drain-select, promote, authorize, publish; and a direct write.
    let staged = random_hash();
    stage_hash(&coordinator, &staged, 0x51).await;
    let candidate = drain_candidate::candidate(&coordinator, &staged).await;
    let BeginOutcome::Admitted(promotion) = coordinator
        .begin_promotion(&candidate, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit promotion");
    };
    let claim = promotion.write_claim().expect("promotion claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize promotion");
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion,
                IoObservation::Valid(manifest(
                    "statement-cache/remote",
                    0x52,
                    EpochAuthority::Remote
                )),
                FragmentWriteSettlement::Decisive,
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );
    let direct = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&direct, &legacy_key(&direct), write_claim())
        .await
        .expect("begin direct write")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    coordinator
        .authorize_write_claim(intent.write_claim().expect("direct claim"))
        .await
        .expect("authorize direct write");
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&intent.object_key, 0x53, EpochAuthority::Remote)),
                FragmentWriteSettlement::Decisive,
            )
            .await
            .expect("commit direct write"),
        CommitVerdict::Published
    );

    let sites = cached_sites();
    let literals: BTreeSet<&str> = sites.iter().map(|site| site.sql.as_str()).collect();
    let prepared = prepared_statements();
    assert!(
        !prepared.is_empty(),
        "a promotion and a direct write prepared nothing: the cache is not wired in"
    );
    for sql in &prepared {
        assert!(
            literals.contains(sql),
            "a statement was cached that is not the literal at any `*_cached(` call site: {sql}"
        );
    }
    // The lifecycle must have reached the statements whose plans matter most.
    for pin in PINS.iter().filter(|pin| !pin.indexes.is_empty()) {
        let site = sites
            .iter()
            .find(|site| pin_matches(pin, site))
            .unwrap_or_else(|| panic!("pin {} matches no call site", pin.name));
        assert!(
            prepared.contains(&site.sql.as_str()),
            "the real lifecycle never prepared {}: the gate would only be source-deep",
            pin.name
        );
    }
}

// ---------------------------------------------------------------------------
// (b) EXPLAIN gate: even a GENERIC plan is safe on a skewed population
// ---------------------------------------------------------------------------

/// Every `Node Type` / relation / index in an EXPLAIN (FORMAT JSON) tree.
fn plan_nodes(value: &serde_json::Value, out: &mut Vec<(String, Option<String>, Option<String>)>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(node_type) = map.get("Node Type").and_then(|v| v.as_str()) {
                out.push((
                    node_type.to_owned(),
                    map.get("Relation Name")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    map.get("Index Name")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                ));
            }
            for child in map.values() {
                plan_nodes(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                plan_nodes(item, out);
            }
        }
        _ => {}
    }
}

async fn single_text(direct: &Client, sql: &str) -> String {
    for message in direct.simple_query(sql).await.expect("simple query") {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).expect("non-null text").to_owned();
        }
    }
    panic!("no row from {sql}");
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn every_cached_statement_has_a_safe_generic_plan_on_a_skewed_population() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    // Planner-only bulk rows: the selective states are a handful among tens of
    // thousands, which is the shape that makes a lost partial index expensive.
    direct
        .batch_execute(
            "INSERT INTO lore_fragment_lifecycle(hash,current_epoch,state,manifest_id,last_fence,active_operation)
               SELECT decode(md5(i::text)||md5(i::text),'hex'),1,
                 CASE WHEN i%3=0 THEN 3 WHEN i%3=1 THEN 4 ELSE 8 END,
                 CASE WHEN i%3<>2 THEN decode(repeat('aa',32),'hex') END,1,
                 CASE WHEN i%3=0 THEN decode(repeat('ee',16),'hex') END
               FROM generate_series(1,30000) i;
             INSERT INTO lore_fragment_epochs(hash,epoch,authority,object_key,manifest_id,size_payload,size_content,decoded_hash,payload_flags,fence)
               SELECT hash,1,1,encode(hash,'hex')||'.s1',decode(repeat('aa',32),'hex'),128,128,hash,0,1 FROM lore_fragment_lifecycle;
             INSERT INTO lore_fragment_stage_custody(hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes)
               SELECT hash,1,1,0,128,clock_timestamp(),1,1024 FROM lore_fragment_lifecycle;
             INSERT INTO lore_fragment_write_claims(logical_request_id,attempt_id,hash,epoch,fence,authority,object_key,body_blake3,body_size,state,send_not_after,hard_not_after,prepared_at,authorized_at,settled_at)
               SELECT decode(md5('l'||i),'hex'),decode(md5('a'||i),'hex'),decode(md5(i::text)||md5(i::text),'hex'),1,1,2,'skew-'||i,
                 decode(repeat('cc',32),'hex'),1,
                 CASE WHEN i%2=0 THEN 2 ELSE 4 END,
                 now()-interval '2 hours',now()-interval '1 hour',now()-interval '3 hours',
                 now()-interval '2 hours',now()-interval '30 minutes'
               FROM generate_series(1,40000) i;
             INSERT INTO lore_fragment_write_claims(logical_request_id,attempt_id,hash,epoch,fence,authority,object_key,body_blake3,body_size,state,send_not_after,hard_not_after,prepared_at,authorized_at,settled_at)
               SELECT decode(md5('L'||i),'hex'),decode(md5('A'||i),'hex'),decode(md5((i*3)::text)||md5((i*3)::text),'hex'),1,1,2,'live-'||i,
                 decode(repeat('cc',32),'hex'),1,
                 CASE i%3 WHEN 0 THEN 0 WHEN 1 THEN 1 ELSE 3 END,
                 now()+interval '1 hour',now()+interval '2 hours',now()-interval '1 hour',
                 CASE WHEN i%3<>0 THEN now()-interval '30 minutes' END,
                 CASE WHEN i%3=2 THEN now()-interval '10 minutes' END
               FROM generate_series(1,12) i;
             INSERT INTO lore_fragment_associations(hash,repository_id,context,association_epoch,state,repository_generation)
               SELECT decode(md5(i::text)||md5(i::text),'hex'),decode(md5((i%7)::text),'hex'),decode('00','hex'),1,
                 CASE WHEN i%1000=0 THEN 0 ELSE 1 END,1
               FROM generate_series(1,60000) i;
             ANALYZE lore_fragment_associations;",
        )
        .await
        .expect("insert the skewed population");
    // A dozen real Staged heads, so the recovery index has real members.
    for index in 0..12u8 {
        stage_hash(&coordinator, &[index; 32], 0x61).await;
    }
    direct
        .batch_execute(
            "ANALYZE lore_fragment_lifecycle; ANALYZE lore_fragment_epochs; \
             ANALYZE lore_fragment_stage_custody; ANALYZE lore_fragment_write_claims;",
        )
        .await
        .expect("analyze");
    let claims_by_state = direct
        .query(
            "SELECT state, count(*) FROM lore_fragment_write_claims GROUP BY state ORDER BY state",
            &[],
        )
        .await
        .expect("claim skew");
    let skew: Vec<(i16, i64)> = claims_by_state
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let barrier: i64 = skew
        .iter()
        .filter(|(s, _)| [0, 1, 3].contains(s))
        .map(|(_, n)| n)
        .sum();
    let terminal: i64 = skew
        .iter()
        .filter(|(s, _)| [2, 4].contains(s))
        .map(|(_, n)| n)
        .sum();
    assert!(
        barrier <= 12 && terminal >= 40_000,
        "the fixture must be skewed toward terminal claims: {skew:?}"
    );

    // Everything below is the generic plan: values are irrelevant to it, so
    // every parameter is bound NULL. A session on `force_generic_plan` is the
    // worst case the pooled `force_custom_plan` setting exists to avoid.
    direct
        .batch_execute("SET plan_cache_mode = force_generic_plan")
        .await
        .expect("force generic plans on the probe session");
    assert_eq!(show(&direct).await, "force_generic_plan");

    let sites = distinct_sites();
    assert!(!sites.is_empty());
    let mut reports = Vec::new();
    for (ordinal, site) in sites.iter().enumerate() {
        let pin = PINS
            .iter()
            .find(|pin| pin_matches(pin, site))
            .unwrap_or_else(|| panic!("{} has no pin: {}", site.file, site.normalized()));
        let parameters = (1..=99usize)
            .rev()
            .find(|n| site.sql.contains(&format!("${n}")))
            .unwrap_or(0);
        let name = format!("cached_probe_{ordinal}");
        direct
            .batch_execute(&format!("PREPARE {name} AS {}", site.sql))
            .await
            .unwrap_or_else(|e| panic!("{}: PREPARE failed: {e}: {}", pin.name, site.normalized()));
        let arguments = if parameters == 0 {
            String::new()
        } else {
            format!("({})", vec!["NULL"; parameters].join(","))
        };
        let json = single_text(
            &direct,
            &format!("EXPLAIN (FORMAT JSON) EXECUTE {name}{arguments}"),
        )
        .await;
        let plan: serde_json::Value = serde_json::from_str(&json).expect("EXPLAIN JSON");
        let mut nodes = Vec::new();
        plan_nodes(&plan, &mut nodes);
        assert!(!nodes.is_empty(), "{}: empty plan {json}", pin.name);

        let used: BTreeSet<&str> = nodes.iter().filter_map(|(_, _, i)| i.as_deref()).collect();
        // The partial-index bearing statements must reach their index even
        // though the planner cannot see the bound values.
        for index in pin.indexes {
            assert!(
                used.contains(index),
                "{}: generic plan does not use {index} (used {used:?}); the pooled custom-plan \
                 setting would be the only thing keeping this statement fast.\n{json}",
                pin.name
            );
        }
        for (node_type, relation, _) in &nodes {
            if node_type == "Seq Scan"
                && matches!(
                    relation.as_deref(),
                    Some("lore_fragment_lifecycle" | "lore_fragment_write_claims")
                )
            {
                panic!(
                    "{}: generic plan scans {relation:?} sequentially on a {}-row population.\n{json}",
                    pin.name, 30_000
                );
            }
        }
        reports.push(format!("{}: indexes={used:?}", pin.name));
    }
    println!(
        "generic plans verified for {} cached statements:",
        sites.len()
    );
    for report in reports {
        println!("  {report}");
    }

    // Control 1: the gate can go red. The barrier statement re-spelled with a
    // BOUND state list (INV-FJ) must lose the partial index and scan the claims
    // table under a generic plan. If it did not, the assertions above would
    // hold for any spelling and prove nothing about this one.
    direct
        .batch_execute(
            "PREPARE bad_barrier(bytea, smallint[]) AS \
             SELECT state, send_not_after, hard_not_after FROM lore_fragment_write_claims \
              WHERE hash = $1 AND state = ANY($2) AND hard_not_after > clock_timestamp() \
              ORDER BY logical_request_id, attempt_id FOR UPDATE",
        )
        .await
        .expect("prepare the bound-spelling control");
    let bad = explain_nodes(&direct, "bad_barrier", "(NULL, NULL)").await;
    assert!(
        bad.iter().any(|(node, relation, _)| node == "Seq Scan"
            && relation.as_deref() == Some("lore_fragment_write_claims")),
        "control: a bound state list must degrade to a sequential scan of the claims table \
         under a generic plan, or the gate cannot detect the INV-FJ regression: {bad:?}"
    );
    assert!(
        !bad.iter()
            .any(|(_, _, index)| index.as_deref() == Some("lore_fragment_write_claims_barrier")),
        "control: the barrier index must be unreachable from a bound state list: {bad:?}"
    );

    // Control 2: the one cached statement that binds a state against a partial
    // index (the lifecycle fanout plan, `state = $2` over
    // `lore_fragment_associations_live_fanout`). Its partial index is reachable
    // only on a CUSTOM plan; the generic plan falls back to the hash-prefixed
    // primary key, bounded but not the index the schema built for it. Nothing
    // but the pooled `force_custom_plan` setting selects the better plan.
    let fanout_pin = PINS
        .iter()
        .find(|pin| pin.name == "lifecycle_fanout_plan")
        .expect("fanout pin");
    let fanout_site = sites
        .iter()
        .find(|site| pin_matches(fanout_pin, site))
        .expect("fanout statement");
    direct
        .batch_execute(&format!("PREPARE fanout_probe AS {}", fanout_site.sql))
        .await
        .expect("prepare the fanout statement");
    let arguments = "(decode(repeat('ab',32),'hex'), 0)";
    direct
        .batch_execute("SET plan_cache_mode = force_custom_plan")
        .await
        .expect("custom plans");
    let custom = explain_nodes(&direct, "fanout_probe", arguments).await;
    direct
        .batch_execute("SET plan_cache_mode = force_generic_plan")
        .await
        .expect("generic plans");
    let generic = explain_nodes(&direct, "fanout_probe", arguments).await;
    let index_of = |nodes: &[(String, Option<String>, Option<String>)]| {
        nodes
            .iter()
            .filter_map(|(_, _, index)| index.clone())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        index_of(&custom),
        BTreeSet::from(["lore_fragment_associations_live_fanout".to_owned()]),
        "custom plan with a literal live state: {custom:?}"
    );
    assert_eq!(
        index_of(&generic),
        BTreeSet::from(["lore_fragment_associations_pkey".to_owned()]),
        "generic plan: {generic:?}"
    );
    assert!(
        !generic.iter().any(|(node, _, _)| node == "Seq Scan"),
        "even the generic fanout plan must not scan the associations table: {generic:?}"
    );
}

/// `EXPLAIN (FORMAT JSON) EXECUTE name<arguments>` flattened to nodes.
async fn explain_nodes(
    direct: &Client,
    name: &str,
    arguments: &str,
) -> Vec<(String, Option<String>, Option<String>)> {
    let json = single_text(
        direct,
        &format!("EXPLAIN (FORMAT JSON) EXECUTE {name}{arguments}"),
    )
    .await;
    let plan: serde_json::Value = serde_json::from_str(&json).expect("EXPLAIN JSON");
    let mut nodes = Vec::new();
    plan_nodes(&plan, &mut nodes);
    assert!(!nodes.is_empty(), "empty plan {json}");
    nodes
}
