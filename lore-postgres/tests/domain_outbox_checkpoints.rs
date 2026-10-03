// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step C: receiver membership, the checkpoint vector, and the bounded
//! `consumer_safe` evaluator (`lore-postgres/src/domain/outbox/{membership,checkpoint,evaluator}.rs`).
//!
//! Real Postgres only, `#[ignore]`. Every case acquires its own
//! [`case_namespace::CaseNamespace`] schema -- load-bearing here, not
//! decorative, since [`evaluate_consumer_safe`] and every membership/checkpoint
//! function scan by `cell_id` with no other isolation.
//!
//! Two client kinds, matching the module's own mixed surface: `join_receiver`,
//! `readiness_cas`, `retire_generation`, `report_checkpoint`,
//! `evaluate_consumer_safe`, and `relay::claim_batch` take
//! `&mut deadpool_postgres::Client` (they open their own internal
//! transaction); `ensure_membership_state`, `read_membership_state`,
//! `set_current_placement`, `record_capture`, `record_baseline`,
//! `read_membership_snapshot`, `checkpoint::read_checkpoint`, and
//! `relay::record_broker_accepted` take `&impl GenericClient`, satisfied by a
//! raw `tokio_postgres::Client` -- the same split `domain_outbox_relay.rs`
//! already established for Step A.
//!
//! The evaluator's batch-seeding tests write `broker_accepted` rows directly
//! by SQL rather than through `append()` + `relay::claim_batch` +
//! `relay::record_broker_accepted`, to seed 2,500 rows in one transaction
//! without 2,500 round trips through the full producer/relay pipeline.
//! `append()`/`relay`'s own correctness is Step A's test responsibility
//! (`domain_outbox.rs`, `domain_outbox_relay.rs`); this file only needs rows
//! that are shaped like what those functions would have produced.

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "common/fixture_resolution.rs"]
mod fixture_resolution;

use std::time::Duration;

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::outbox::CapturedPosition;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::PoisonEntry;
use lore_postgres::domain::outbox::SafetyBlock;
use lore_postgres::domain::outbox::SequenceGap;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::checkpoint;
use lore_postgres::domain::outbox::evaluate_consumer_safe;
use lore_postgres::domain::outbox::evaluator::MAX_EVALUATION_BATCH;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::relay;
use lore_postgres::domain::outbox::relay::BrokerAcceptanceRecord;
use lore_postgres::domain::outbox::report_checkpoint;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use serde_json::Value;
use tokio_postgres::Client;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn ensure_schema_bootstrapped(url: &str) {
    let _ = PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap the domain schema (including outbox tables) for this namespace");
}

/// A raw `NoTls` connection, for the functions bound on `&impl GenericClient`.
async fn pg_client(url: &str) -> Client {
    ensure_schema_bootstrapped(url).await;
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test access");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// A `deadpool_postgres::Client`, for the functions that open their own
/// internal transaction.
async fn deadpool_client(url: &str) -> deadpool_postgres::Client {
    let pool = build_pool(url, 8, &TlsConfig::default()).expect("build pool");
    pool.get()
        .await
        .expect("checkout deadpool connection")
        .into_inner()
}

fn rand_cell_id() -> String {
    format!("cell-{:016x}", rand::random::<u64>())
}

fn rand_repository_id() -> [u8; 16] {
    rand::random()
}

fn rand_aggregate_id() -> [u8; 16] {
    rand::random()
}

async fn current_membership_version(raw: &Client, cell_id: &str) -> i64 {
    membership::read_membership_state(raw, cell_id)
        .await
        .expect("read membership state")
        .expect("membership state row present")
        .membership_version
}

/// Append one pending row via the real production `append()` path.
async fn append_pending(
    client: &mut Client,
    cell_id: &str,
    repository_id: &[u8],
    ordinal: u64,
) -> Uuid {
    let aggregate_id = rand_aggregate_id();
    let version = AggregateVersion::ordinal_only(ordinal).encode();
    let tx = client.transaction().await.expect("begin append tx");
    let event = OutboxEvent {
        cell_id,
        repository_id,
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id: &aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(&tx, &event).await.expect("append pending event");
    tx.commit().await.expect("commit append");
    appended.event_id
}

/// Move one pending row to `broker_accepted` at a given stream/epoch/sequence,
/// through the real production claim/accept path (Step A's own functions).
async fn accept_one_via_relay(
    raw: &Client,
    deadpool: &mut deadpool_postgres::Client,
    stream_identity: &str,
    stream_epoch: i64,
    broker_sequence: i64,
) -> Uuid {
    let mut claimed = relay::claim_batch(deadpool, "checkpoints-test", 10, Duration::from_secs(30))
        .await
        .expect("claim the just-appended row");
    let claim = claimed.pop().expect("exactly one claimable row");
    let outcome = relay::record_broker_accepted(
        raw,
        claim.event.event_id,
        claim.claim_generation,
        &BrokerAcceptanceRecord {
            stream_identity: stream_identity.to_string(),
            stream_epoch,
            broker_sequence,
            gateway_response_id: format!("gw-{broker_sequence}"),
            publisher_contract_version: 1,
        },
    )
    .await
    .expect("record broker acceptance");
    assert_eq!(
        outcome,
        relay::CasOutcome::Applied,
        "the claim must still be held"
    );
    claim.event.event_id
}

/// Directly write `count` already-`broker_accepted` rows for one stream/epoch,
/// with consecutive broker sequences starting at 1. Bypasses `append()`/
/// `relay` on purpose -- see the module docs.
async fn seed_broker_accepted_rows(
    client: &mut Client,
    cell_id: &str,
    repository_id: &[u8],
    stream_identity: &str,
    stream_epoch: i64,
    count: i64,
) {
    let tx = client.transaction().await.expect("begin bulk seed tx");
    let aggregate_version = vec![0u8; 8];
    for seq in 1..=count {
        let event_id = Uuid::now_v7();
        let mut idempotency_key = [0u8; 32];
        idempotency_key[24..].copy_from_slice(&seq.to_be_bytes());
        let mut aggregate_id = [0u8; 16];
        aggregate_id[8..].copy_from_slice(&seq.to_be_bytes());
        tx.execute(
            "INSERT INTO lore_outbox_events \
                 (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                  event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                  payload_schema_version, payload, state, created_at, available_at, \
                  stream_identity, stream_epoch, broker_sequence, gateway_response_id, \
                  publisher_contract_version, broker_accepted_at) \
             VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', \
                     'broker_accepted', clock_timestamp(), clock_timestamp(), \
                     $7, $8, $9, $10, 1, clock_timestamp())",
            &[
                &event_id,
                &cell_id,
                &idempotency_key.as_slice(),
                &repository_id,
                &aggregate_id.as_slice(),
                &aggregate_version,
                &stream_identity,
                &stream_epoch,
                &seq,
                &format!("gw-bulk-{seq}"),
            ],
        )
        .await
        .expect("seed one broker_accepted row");
    }
    tx.commit().await.expect("commit bulk seed");
}

async fn event_state(raw: &Client, event_id: Uuid) -> String {
    raw.query_one(
        "SELECT state FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("read event state")
    .get("state")
}

async fn count_by_state(raw: &Client, cell_id: &str, stream_identity: &str, state: &str) -> i64 {
    raw.query_one(
        "SELECT count(*) AS n FROM lore_outbox_events \
             WHERE cell_id = $1 AND stream_identity = $2 AND state = $3",
        &[&cell_id, &stream_identity, &state],
    )
    .await
    .expect("count rows by state")
    .get("n")
}

/// Install a reset fence directly by SQL, bypassing `reset::accept_reset`.
/// `event_relay_reset.rs` owns proving the receipt transaction itself; this
/// file only needs the fence's effect on the evaluator.
async fn install_reset_fence(raw: &Client, cell_id: &str, old_epoch: i64, new_epoch: i64) {
    raw.execute(
        "INSERT INTO lore_outbox_reset_generations \
             (cell_id, reset_generation, detection_id, reset_fingerprint, \
              broker_reset_identity, old_stream_identity, old_stream_epoch, \
              new_stream_identity, new_stream_epoch, reason_code, placement_revision, \
              detected_at_unix_ms, emitter_identity, evidence_id, ack_bytes, state, \
              persisted_at) \
         VALUES ($1, 1, 'test-detection', $2, 'broker-x', 'DURABLE-x', $3, 'DURABLE-x', $4, 2, 0, \
                 0, 'spiffe://test/cell/test/wp110', 'ev-1', $5, 'reset_in_progress', \
                 clock_timestamp())",
        &[
            &cell_id,
            &vec![0x11u8; 32],
            &old_epoch,
            &new_epoch,
            &vec![1u8, 2, 3],
        ],
    )
    .await
    .expect("install a reset fence row");
}

// ---------------------------------------------------------------------------
// 1. Membership
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn join_receiver_allocates_strictly_increasing_generations_and_bumps_membership_version() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "join-generation_id").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let cell_id = rand_cell_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    assert_eq!(state.membership_version, 1);
    assert_eq!(state.next_membership_generation, 1);

    let mut deadpool = deadpool_client(&url).await;
    let first = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-a-1", 1)
        .await
        .expect("first join");
    let MembershipCas::Applied {
        membership_version: v1,
        membership_generation: g1,
    } = first
    else {
        panic!("expected Applied, got {first:?}");
    };
    assert_eq!(g1, 1);

    let second = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-a-2", v1)
        .await
        .expect("second join");
    let MembershipCas::Applied {
        membership_version: v2,
        membership_generation: g2,
    } = second
    else {
        panic!("expected Applied, got {second:?}");
    };
    assert_eq!(g2, 2);
    assert!(
        g2 > g1,
        "generations must strictly increase: {g1} then {g2}"
    );
    assert!(
        v2 > v1,
        "membership_version must bump on every join: {v1} then {v2}"
    );

    // A join against a stale expected_membership_version is refused with the
    // current version, not silently applied against the caller's stale read.
    let stale = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-a-3", v1)
        .await
        .expect("stale join call itself must not error");
    assert_eq!(
        stale,
        MembershipCas::VersionConflict {
            current_membership_version: v2
        }
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn capture_baseline_and_readiness_cas_succeed_when_placement_still_matches_the_capture() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "cas-ok").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    let placed = membership::set_current_placement(
        &raw,
        &cell_id,
        "DURABLE-x",
        1,
        0,
        state.membership_version,
    )
    .await
    .expect("set current placement");
    assert!(matches!(placed, MembershipCas::Applied { .. }));

    let version_after_place = current_membership_version(&raw, &cell_id).await;
    let joined =
        membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version_after_place)
            .await
            .expect("join receiver");
    let MembershipCas::Applied {
        membership_generation: generation_id,
        ..
    } = joined
    else {
        panic!("expected Applied, got {joined:?}");
    };

    let captured = CapturedPosition {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        start_sequence: 0,
    };
    let cap = membership::record_capture(&raw, &cell_id, "loreserver-1", generation_id, &captured)
        .await
        .expect("record capture");
    assert!(matches!(cap, MembershipCas::Applied { .. }));

    let base = membership::record_baseline(&raw, &cell_id, "loreserver-1", generation_id)
        .await
        .expect("record baseline");
    assert!(matches!(base, MembershipCas::Applied { .. }));

    // The readiness CAS requires a persisted checkpoint at the captured
    // placement before it will succeed -- a baseline alone is not enough.
    let version_for_report = current_membership_version(&raw, &cell_id).await;
    let report = CheckpointReport {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        receiver_identity: "loreserver-1".to_string(),
        membership_generation: generation_id,
        membership_version: version_for_report,
        contiguous_frontier: 10,
        gaps: Vec::new(),
        poison: Vec::new(),
    };
    let checkpointed = report_checkpoint(&mut deadpool, &cell_id, &report)
        .await
        .expect("report checkpoint");
    assert_eq!(
        checkpointed,
        CheckpointOutcome::Applied {
            contiguous_frontier: 10
        }
    );

    let ready = membership::readiness_cas(&mut deadpool, &cell_id, "loreserver-1", generation_id)
        .await
        .expect("readiness cas");
    assert!(matches!(ready, MembershipCas::Applied { .. }));

    let snapshot = membership::read_membership_snapshot(&raw, &cell_id)
        .await
        .expect("read snapshot")
        .expect("snapshot present");
    let member = snapshot
        .members
        .iter()
        .find(|m| m.membership_generation == generation_id)
        .expect("the joined generation");
    assert_eq!(member.state, "ready");
    assert!(member.ready_at.is_some());

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn readiness_cas_retires_the_generation_when_placement_moved_since_capture() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "cas-retire").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(&raw, &cell_id, "DURABLE-x", 1, 0, state.membership_version)
        .await
        .expect("place at DURABLE-x/1");

    let version = current_membership_version(&raw, &cell_id).await;
    let joined = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version)
        .await
        .expect("join receiver");
    let MembershipCas::Applied {
        membership_generation: generation_id,
        ..
    } = joined
    else {
        panic!("expected Applied, got {joined:?}");
    };

    let captured = CapturedPosition {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        start_sequence: 0,
    };
    membership::record_capture(&raw, &cell_id, "loreserver-1", generation_id, &captured)
        .await
        .expect("record capture");
    membership::record_baseline(&raw, &cell_id, "loreserver-1", generation_id)
        .await
        .expect("record baseline");

    // The epoch moves BETWEEN capture and the readiness CAS -- the exact
    // boundary the contract's `reset-between-capture-and-baseline`/
    // `...-baseline-and-drain`/`...-drain-and-cas` transitions name.
    let version_before_move = current_membership_version(&raw, &cell_id).await;
    membership::set_current_placement(&raw, &cell_id, "DURABLE-y", 2, 0, version_before_move)
        .await
        .expect("move placement to DURABLE-y/2");

    let result = membership::readiness_cas(&mut deadpool, &cell_id, "loreserver-1", generation_id)
        .await
        .expect("readiness cas call itself must not error");
    assert!(
        matches!(result, MembershipCas::PlacementMoved { .. }),
        "expected PlacementMoved, got {result:?}"
    );

    let snapshot = membership::read_membership_snapshot(&raw, &cell_id)
        .await
        .expect("read snapshot")
        .expect("snapshot present");
    let member = snapshot
        .members
        .iter()
        .find(|m| m.membership_generation == generation_id)
        .expect("the joined generation");
    assert_eq!(
        member.state, "retired",
        "a placement mismatch at the readiness CAS must retire the generation"
    );

    // A retired generation cannot report a checkpoint.
    let version_after_retire = current_membership_version(&raw, &cell_id).await;
    let report = CheckpointReport {
        stream_identity: "DURABLE-y".to_string(),
        stream_epoch: 2,
        receiver_identity: "loreserver-1".to_string(),
        membership_generation: generation_id,
        membership_version: version_after_retire,
        contiguous_frontier: 0,
        gaps: Vec::new(),
        poison: Vec::new(),
    };
    let outcome = report_checkpoint(&mut deadpool, &cell_id, &report)
        .await
        .expect("report_checkpoint call itself must not error");
    assert_eq!(outcome, CheckpointOutcome::RetiredGeneration);

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// 2. Checkpoints
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_later_report_advances_the_frontier_and_a_lower_one_never_moves_it_backward() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "frontier").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(&raw, &cell_id, "DURABLE-x", 1, 0, state.membership_version)
        .await
        .expect("place");
    let version = current_membership_version(&raw, &cell_id).await;
    let joined = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version)
        .await
        .expect("join");
    let MembershipCas::Applied {
        membership_generation: generation_id,
        ..
    } = joined
    else {
        panic!("unexpected {joined:?}");
    };
    let version = current_membership_version(&raw, &cell_id).await;

    let base_report = |frontier: i64| CheckpointReport {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        receiver_identity: "loreserver-1".to_string(),
        membership_generation: generation_id,
        membership_version: version,
        contiguous_frontier: frontier,
        gaps: Vec::new(),
        poison: Vec::new(),
    };

    let first = report_checkpoint(&mut deadpool, &cell_id, &base_report(900))
        .await
        .expect("first report");
    assert_eq!(
        first,
        CheckpointOutcome::Applied {
            contiguous_frontier: 900
        }
    );

    let second = report_checkpoint(&mut deadpool, &cell_id, &base_report(930))
        .await
        .expect("second report");
    assert_eq!(
        second,
        CheckpointOutcome::Applied {
            contiguous_frontier: 930
        }
    );

    let regressed = report_checkpoint(&mut deadpool, &cell_id, &base_report(500))
        .await
        .expect("regressed report");
    assert_eq!(
        regressed,
        CheckpointOutcome::FrontierRegressed {
            current_contiguous_frontier: 930
        }
    );

    // The stored vector matches checkpoint-vector.json's `report_shape`
    // fields, persisted and read back through the real production path.
    let record = checkpoint::read_checkpoint(&raw, "DURABLE-x", 1, "loreserver-1", generation_id)
        .await
        .expect("read checkpoint")
        .expect("checkpoint row present");
    assert_eq!(record.stream_identity, "DURABLE-x");
    assert_eq!(record.stream_epoch, 1);
    assert_eq!(record.receiver_identity, "loreserver-1");
    assert_eq!(record.membership_generation, generation_id);
    assert_eq!(
        record.contiguous_frontier, 930,
        "the regressed report must not have moved it"
    );
    assert!(record.gaps.is_empty());
    assert!(record.poison.is_empty());

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_report_cannot_claim_a_frontier_above_its_own_unresolved_gap_or_poison() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "gap-block").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(&raw, &cell_id, "DURABLE-x", 1, 0, state.membership_version)
        .await
        .expect("place");
    let version = current_membership_version(&raw, &cell_id).await;
    let joined = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version)
        .await
        .expect("join");
    let MembershipCas::Applied {
        membership_generation: generation_id,
        ..
    } = joined
    else {
        panic!("unexpected {joined:?}");
    };
    let version = current_membership_version(&raw, &cell_id).await;

    // A report claiming a frontier PAST its own unresolved gap is refused
    // before it ever touches the row, exactly like the fixture's
    // "acknowledgement-above-a-gap-does-not-advance-the-frontier" case.
    let bad = CheckpointReport {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        receiver_identity: "loreserver-1".to_string(),
        membership_generation: generation_id,
        membership_version: version,
        contiguous_frontier: 930,
        gaps: vec![SequenceGap { from: 917, to: 918 }],
        poison: Vec::new(),
    };
    assert!(
        report_checkpoint(&mut deadpool, &cell_id, &bad)
            .await
            .is_err(),
        "a frontier claimed above its own gap must be refused by the production entry point"
    );

    // The correct report -- frontier held at the gap -- is accepted and
    // persists the gap and poison arrays intact.
    let good = CheckpointReport {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        receiver_identity: "loreserver-1".to_string(),
        membership_generation: generation_id,
        membership_version: version,
        contiguous_frontier: 916,
        gaps: vec![SequenceGap { from: 917, to: 918 }],
        poison: vec![PoisonEntry {
            broker_sequence: 950,
            class: "UNSUPPORTED_SCHEMA".to_string(),
        }],
    };
    let outcome = report_checkpoint(&mut deadpool, &cell_id, &good)
        .await
        .expect("the held-at-the-gap report");
    assert_eq!(
        outcome,
        CheckpointOutcome::Applied {
            contiguous_frontier: 916
        }
    );

    let record = checkpoint::read_checkpoint(&raw, "DURABLE-x", 1, "loreserver-1", generation_id)
        .await
        .expect("read checkpoint")
        .expect("checkpoint row present");
    assert_eq!(record.contiguous_frontier, 916);
    assert_eq!(record.gaps, vec![SequenceGap { from: 917, to: 918 }]);
    assert_eq!(
        record.poison,
        vec![PoisonEntry {
            broker_sequence: 950,
            class: "UNSUPPORTED_SCHEMA".to_string(),
        }]
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// 2b. Retirement (WP-115 row 68: `loreserver outbox retire-generation`)
// ---------------------------------------------------------------------------

/// A placed cell, for the retirement cases.
async fn placed_cell(raw: &Client, stream_identity: &str, stream_epoch: i64) -> String {
    let cell_id = rand_cell_id();
    let state = membership::ensure_membership_state(raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    cell_id
}

const RETIRE_ACTOR: &str = "kv";
const RETIRE_REASON: &str = "replica decommissioned";

async fn retire(
    deadpool: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    generation: i64,
) -> MembershipCas {
    retire_with(deadpool, cell_id, receiver_identity, generation, false).await
}

async fn retire_with(
    deadpool: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    generation: i64,
    confirm_receiver_stopped: bool,
) -> MembershipCas {
    membership::retire_generation(
        deadpool,
        cell_id,
        receiver_identity,
        generation,
        RETIRE_ACTOR,
        RETIRE_REASON,
        confirm_receiver_stopped,
    )
    .await
    .expect("retire call")
}

/// `(retirement_actor, retirement_reason, retirement_recorded_at IS NOT NULL)`.
async fn retirement_audit(
    raw: &Client,
    cell_id: &str,
    receiver_identity: &str,
    generation: i64,
) -> (Option<String>, Option<String>, bool) {
    let row = raw
        .query_one(
            "SELECT retirement_actor, retirement_reason, \
                    retirement_recorded_at IS NOT NULL AS recorded \
               FROM lore_outbox_receiver_membership \
              WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3",
            &[&cell_id, &receiver_identity, &generation],
        )
        .await
        .expect("read retirement audit");
    (
        row.get("retirement_actor"),
        row.get("retirement_reason"),
        row.get("recorded"),
    )
}

/// `retirement_basis`: which proof retired the generation (migration 0008).
async fn retirement_basis(
    raw: &Client,
    cell_id: &str,
    receiver_identity: &str,
    generation: i64,
) -> Option<String> {
    raw.query_one(
        "SELECT retirement_basis FROM lore_outbox_receiver_membership \
          WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3",
        &[&cell_id, &receiver_identity, &generation],
    )
    .await
    .expect("read retirement basis")
    .get("retirement_basis")
}

/// The receiver's graceful-shutdown write: its final checkpoint at `frontier`
/// and the `draining` marker, in one call.
async fn drain(
    deadpool: &mut deadpool_postgres::Client,
    raw: &Client,
    cell_id: &str,
    receiver_identity: &str,
    generation: i64,
    frontier: i64,
) -> CheckpointOutcome {
    let report = CheckpointReport {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        receiver_identity: receiver_identity.to_string(),
        membership_generation: generation,
        membership_version: current_membership_version(raw, cell_id).await,
        contiguous_frontier: frontier,
        gaps: Vec::new(),
        poison: Vec::new(),
    };
    checkpoint::report_draining_checkpoint(deadpool, cell_id, &report)
        .await
        .expect("draining checkpoint call")
}

async fn member_state(raw: &Client, cell_id: &str, generation: i64) -> String {
    membership::read_membership_snapshot(raw, cell_id)
        .await
        .expect("read snapshot")
        .expect("snapshot present")
        .members
        .iter()
        .find(|m| m.membership_generation == generation)
        .expect("the generation")
        .state
        .clone()
}

/// Neither contract precondition holds for a generation that only joined: no
/// checkpoint at the current placement, no ready successor. Retiring it anyway
/// would drop it from the required set, so the call refuses and writes nothing.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_refuses_a_generation_with_no_checkpoint_and_no_ready_successor() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-unproven").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;

    let version = current_membership_version(&raw, &cell_id).await;
    let MembershipCas::Applied {
        membership_generation: generation,
        ..
    } = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version)
        .await
        .expect("join")
    else {
        panic!("join must apply");
    };
    let version_before = current_membership_version(&raw, &cell_id).await;

    let outcome = retire(&mut deadpool, &cell_id, "loreserver-1", generation).await;
    assert_eq!(outcome, MembershipCas::RetirementUnproven);
    assert_eq!(member_state(&raw, &cell_id, generation).await, "joining");
    assert_eq!(
        current_membership_version(&raw, &cell_id).await,
        version_before,
        "a refused retirement must not bump the snapshot version"
    );
    assert_eq!(
        retirement_audit(&raw, &cell_id, "loreserver-1", generation).await,
        (None, None, false),
        "a refused retirement records no audit"
    );

    // An unknown cell is its own answer, not a refusal of the generation.
    let unknown_cell = retire(&mut deadpool, &rand_cell_id(), "loreserver-1", generation).await;
    assert_eq!(unknown_cell, MembershipCas::CellUnknown);
    // So is an unknown generation of a known cell.
    let unknown_generation = retire(&mut deadpool, &cell_id, "loreserver-1", generation + 5).await;
    assert_eq!(unknown_generation, MembershipCas::GenerationNotFound);

    namespace.release().await;
}

/// Graceful drain: a generation whose receiver stopped gracefully (its
/// shutdown marked it `draining`) and whose checkpoint has reached every
/// broker-accepted row on the current stream and epoch retires, records the
/// operator audit with the `graceful_drain` basis, and a second call is
/// idempotent and keeps the first audit.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_retires_a_drained_generation_and_is_idempotent() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-drained").await;
    let url = namespace.pg_url().to_owned();
    let mut raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    // Accepted rows at 1..=40, exactly the frontier the receiver reports.
    seed_broker_accepted_rows(
        &mut raw,
        &cell_id,
        &rand_repository_id(),
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let version_before = current_membership_version(&raw, &cell_id).await;

    // The receiver stops gracefully: the same frontier it already reported,
    // plus the marker. Neither bumps the snapshot version.
    assert_eq!(
        drain(
            &mut deadpool,
            &raw,
            &cell_id,
            "loreserver-1",
            generation,
            40
        )
        .await,
        CheckpointOutcome::Applied {
            contiguous_frontier: 40
        }
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "draining");
    assert_eq!(
        current_membership_version(&raw, &cell_id).await,
        version_before,
        "the draining marker leaves the required set, and so the version, unchanged"
    );

    let outcome = retire(&mut deadpool, &cell_id, "loreserver-1", generation).await;
    assert_eq!(
        outcome,
        MembershipCas::Applied {
            membership_version: version_before + 1,
            membership_generation: generation,
        }
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "retired");
    assert_eq!(
        current_membership_version(&raw, &cell_id).await,
        version_before + 1
    );
    assert_eq!(
        retirement_audit(&raw, &cell_id, "loreserver-1", generation).await,
        (
            Some(RETIRE_ACTOR.to_owned()),
            Some(RETIRE_REASON.to_owned()),
            true
        )
    );
    assert_eq!(
        retirement_basis(&raw, &cell_id, "loreserver-1", generation)
            .await
            .as_deref(),
        Some("graceful_drain")
    );

    // A rerun by someone else, for another reason, writes nothing.
    let again = membership::retire_generation(
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        generation,
        "someone-else",
        "a second reason",
        true,
    )
    .await
    .expect("second retire call");
    assert_eq!(again, MembershipCas::AlreadyRecorded);
    assert_eq!(
        retirement_audit(&raw, &cell_id, "loreserver-1", generation).await,
        (
            Some(RETIRE_ACTOR.to_owned()),
            Some(RETIRE_REASON.to_owned()),
            true
        ),
        "the first audit stands"
    );
    assert_eq!(
        retirement_basis(&raw, &cell_id, "loreserver-1", generation)
            .await
            .as_deref(),
        Some("graceful_drain"),
        "a rerun with the confirmation does not rewrite the basis"
    );
    assert_eq!(
        current_membership_version(&raw, &cell_id).await,
        version_before + 1
    );

    namespace.release().await;
}

/// WP-115 row 68 (KV ruling 2026-09-28): a caught-up frontier proves the
/// receiver drained, not that it stopped. A `ready` generation whose checkpoint
/// has reached every accepted row is a live receiver as far as the store can
/// tell, so the graceful path refuses it until the receiver's own graceful
/// shutdown marks it `draining`.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_refuses_a_caught_up_live_generation_that_is_not_draining() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-live").await;
    let url = namespace.pg_url().to_owned();
    let mut raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    seed_broker_accepted_rows(
        &mut raw,
        &cell_id,
        &rand_repository_id(),
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let version_before = current_membership_version(&raw, &cell_id).await;

    assert_eq!(
        retire(&mut deadpool, &cell_id, "loreserver-1", generation).await,
        MembershipCas::ReceiverNotStopped {
            state: "ready".to_owned()
        }
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "ready");
    assert_eq!(
        current_membership_version(&raw, &cell_id).await,
        version_before
    );
    assert_eq!(
        retirement_audit(&raw, &cell_id, "loreserver-1", generation).await,
        (None, None, false)
    );

    namespace.release().await;
}

/// A receiver that restarts on the generation its graceful shutdown marked
/// `draining` resumes it: `readiness_cas` moves it back to `ready` without
/// bumping the snapshot version, and the graceful path then refuses it again,
/// because it is live. A `joining` generation has no graceful stop to record,
/// so the draining write refuses it whole.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_draining_generation_that_restarts_resumes_to_ready() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "drain-restart").await;
    let url = namespace.pg_url().to_owned();
    let mut raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    seed_broker_accepted_rows(
        &mut raw,
        &cell_id,
        &rand_repository_id(),
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        40,
    )
    .await;
    assert!(matches!(
        drain(
            &mut deadpool,
            &raw,
            &cell_id,
            "loreserver-1",
            generation,
            40
        )
        .await,
        CheckpointOutcome::Applied { .. }
    ));
    // A repeated shutdown report is idempotent.
    assert!(matches!(
        drain(
            &mut deadpool,
            &raw,
            &cell_id,
            "loreserver-1",
            generation,
            40
        )
        .await,
        CheckpointOutcome::Applied { .. }
    ));
    assert_eq!(member_state(&raw, &cell_id, generation).await, "draining");
    let version = current_membership_version(&raw, &cell_id).await;

    // The restart's bootstrap reports its checkpoint, then the readiness CAS.
    let resumed = membership::readiness_cas(&mut deadpool, &cell_id, "loreserver-1", generation)
        .await
        .expect("readiness cas on a draining generation");
    assert_eq!(
        resumed,
        MembershipCas::Applied {
            membership_version: version,
            membership_generation: generation,
        }
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "ready");
    assert_eq!(current_membership_version(&raw, &cell_id).await, version);
    assert_eq!(
        retire(&mut deadpool, &cell_id, "loreserver-1", generation).await,
        MembershipCas::ReceiverNotStopped {
            state: "ready".to_owned()
        },
        "the resumed receiver is live again"
    );

    // A second receiver that has only joined cannot be marked draining.
    let version = current_membership_version(&raw, &cell_id).await;
    let MembershipCas::Applied {
        membership_generation: joining,
        ..
    } = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-2", version)
        .await
        .expect("join")
    else {
        panic!("join must apply");
    };
    assert_eq!(
        drain(&mut deadpool, &raw, &cell_id, "loreserver-2", joining, 0).await,
        CheckpointOutcome::NotDrainable {
            state: "joining".to_owned()
        }
    );
    assert_eq!(member_state(&raw, &cell_id, joining).await, "joining");
    assert_eq!(
        checkpoint::read_checkpoint(&raw, "DURABLE-x", 1, "loreserver-2", joining)
            .await
            .expect("read checkpoint"),
        None,
        "a refused draining write projects nothing"
    );

    namespace.release().await;
}

/// A `draining` generation whose placement moved is not resumed, and unlike a
/// joining one it is not retired by the refusal either: an operator may still
/// be proving its drain, and the successor the receiver starts outranks it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn readiness_cas_refuses_a_draining_generation_whose_placement_moved_without_retiring_it() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "drain-moved").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        0,
    )
    .await;
    assert!(matches!(
        drain(&mut deadpool, &raw, &cell_id, "loreserver-1", generation, 0).await,
        CheckpointOutcome::Applied { .. }
    ));
    let version = current_membership_version(&raw, &cell_id).await;
    assert!(matches!(
        membership::set_current_placement(&raw, &cell_id, "DURABLE-y", 2, 1, version)
            .await
            .expect("move placement"),
        MembershipCas::Applied { .. }
    ));
    let version = current_membership_version(&raw, &cell_id).await;

    assert_eq!(
        membership::readiness_cas(&mut deadpool, &cell_id, "loreserver-1", generation)
            .await
            .expect("readiness cas"),
        MembershipCas::PlacementMoved {
            current_stream_identity: Some("DURABLE-y".to_owned()),
            current_stream_epoch: Some(2),
        }
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "draining");
    assert_eq!(current_membership_version(&raw, &cell_id).await, version);

    namespace.release().await;
}

/// The escape hatch: a receiver that died without a graceful stop never wrote
/// the marker. With `confirm_receiver_stopped` and a caught-up frontier it
/// retires, and the row records `confirmed_stopped` beside the actor and
/// reason.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_with_a_stop_confirmation_retires_and_records_it() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-confirmed").await;
    let url = namespace.pg_url().to_owned();
    let mut raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    seed_broker_accepted_rows(
        &mut raw,
        &cell_id,
        &rand_repository_id(),
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let version_before = current_membership_version(&raw, &cell_id).await;

    assert_eq!(
        retire_with(&mut deadpool, &cell_id, "loreserver-1", generation, true).await,
        MembershipCas::Applied {
            membership_version: version_before + 1,
            membership_generation: generation,
        }
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "retired");
    assert_eq!(
        retirement_audit(&raw, &cell_id, "loreserver-1", generation).await,
        (
            Some(RETIRE_ACTOR.to_owned()),
            Some(RETIRE_REASON.to_owned()),
            true
        )
    );
    assert_eq!(
        retirement_basis(&raw, &cell_id, "loreserver-1", generation)
            .await
            .as_deref(),
        Some("confirmed_stopped")
    );

    namespace.release().await;
}

/// The review's blocker: a live, ready receiver whose checkpoint is behind a
/// broker-accepted row is refused, not retired. Its checkpoint exists at the
/// current placement, which the old proof took as a drain. Once it reports a
/// frontier at the last accepted row, the same call retires it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_refuses_a_ready_generation_behind_an_accepted_row() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-lagging").await;
    let url = namespace.pg_url().to_owned();
    let mut raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    // Accepted rows at 1..=41; the receiver has acknowledged only through 40.
    seed_broker_accepted_rows(
        &mut raw,
        &cell_id,
        &rand_repository_id(),
        "DURABLE-x",
        1,
        41,
    )
    .await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let version_before = current_membership_version(&raw, &cell_id).await;

    assert_eq!(
        retire(&mut deadpool, &cell_id, "loreserver-1", generation).await,
        MembershipCas::RetirementUnproven
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "ready");
    assert_eq!(
        current_membership_version(&raw, &cell_id).await,
        version_before
    );
    assert_eq!(
        retirement_audit(&raw, &cell_id, "loreserver-1", generation).await,
        (None, None, false)
    );

    // A draining marker does not stand in for the frontier: stopped at 40
    // with an accepted row at 41 is still refused.
    assert_eq!(
        drain(
            &mut deadpool,
            &raw,
            &cell_id,
            "loreserver-1",
            generation,
            40
        )
        .await,
        CheckpointOutcome::Applied {
            contiguous_frontier: 40
        }
    );
    assert_eq!(
        retire(&mut deadpool, &cell_id, "loreserver-1", generation).await,
        MembershipCas::RetirementUnproven
    );
    // Nor does the operator's confirmation.
    assert_eq!(
        retire_with(&mut deadpool, &cell_id, "loreserver-1", generation, true).await,
        MembershipCas::RetirementUnproven
    );

    // The receiver comes back, catches up, and stops again; now it has
    // drained. `report_checkpoint` accepts a draining generation's report.
    let caught_up = CheckpointReport {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        receiver_identity: "loreserver-1".to_string(),
        membership_generation: generation,
        membership_version: version_before,
        contiguous_frontier: 41,
        gaps: Vec::new(),
        poison: Vec::new(),
    };
    assert_eq!(
        report_checkpoint(&mut deadpool, &cell_id, &caught_up)
            .await
            .expect("catch-up report"),
        CheckpointOutcome::Applied {
            contiguous_frontier: 41
        }
    );
    assert!(
        matches!(
            retire(&mut deadpool, &cell_id, "loreserver-1", generation).await,
            MembershipCas::Applied { membership_generation, .. } if membership_generation == generation
        ),
        "a drained generation must retire"
    );

    namespace.release().await;
}

/// A checkpoint at the last accepted row that still carries a poison park has
/// not drained: the parked event is not applied.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_refuses_a_generation_whose_checkpoint_carries_a_park() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-parked").await;
    let url = namespace.pg_url().to_owned();
    let mut raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    seed_broker_accepted_rows(
        &mut raw,
        &cell_id,
        &rand_repository_id(),
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        40,
    )
    .await;
    let version = current_membership_version(&raw, &cell_id).await;
    let parked = CheckpointReport {
        stream_identity: "DURABLE-x".to_string(),
        stream_epoch: 1,
        receiver_identity: "loreserver-1".to_string(),
        membership_generation: generation,
        membership_version: version,
        contiguous_frontier: 40,
        gaps: Vec::new(),
        poison: vec![PoisonEntry {
            broker_sequence: 45,
            class: "UNSUPPORTED_SCHEMA".to_string(),
        }],
    };
    report_checkpoint(&mut deadpool, &cell_id, &parked)
        .await
        .expect("parked report");

    assert_eq!(
        retire(&mut deadpool, &cell_id, "loreserver-1", generation).await,
        MembershipCas::RetirementUnproven
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "ready");

    // The operator path for a permanent park: restart the receiver. Its
    // bootstrap refuses to resume a parked checkpoint and readies a new
    // generation, and the parked one then retires by replacement.
    let successor = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        40,
    )
    .await;
    assert!(successor > generation);
    assert!(
        matches!(
            retire(&mut deadpool, &cell_id, "loreserver-1", generation).await,
            MembershipCas::Applied { membership_generation, .. } if membership_generation == generation
        ),
        "a parked generation must retire once a greater one is ready"
    );
    assert_eq!(member_state(&raw, &cell_id, successor).await, "ready");

    namespace.release().await;
}

/// The reset fence's placeholder is refused by identity and by generation,
/// and so are an empty actor and an empty reason. None of them touch the row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_refuses_the_placeholder_and_an_unaudited_call() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-placeholder").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;
    let generation = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        0,
    )
    .await;
    let version = current_membership_version(&raw, &cell_id).await;
    raw.execute(
        "INSERT INTO lore_outbox_receiver_membership \
             (cell_id, receiver_identity, membership_generation, membership_version, state, \
              created_at, updated_at) \
         VALUES ($1, 'required-replacement-placeholder', 0, $2, 'required_placeholder', \
                 clock_timestamp(), clock_timestamp())",
        &[&cell_id, &version],
    )
    .await
    .expect("install the placeholder row");

    for (receiver, target, actor, reason) in [
        (
            "required-replacement-placeholder",
            0,
            RETIRE_ACTOR,
            RETIRE_REASON,
        ),
        (
            "required-replacement-placeholder",
            generation,
            RETIRE_ACTOR,
            RETIRE_REASON,
        ),
        ("loreserver-1", 0, RETIRE_ACTOR, RETIRE_REASON),
        ("loreserver-1", generation, "", RETIRE_REASON),
        ("loreserver-1", generation, RETIRE_ACTOR, ""),
    ] {
        let refused = membership::retire_generation(
            &mut deadpool,
            &cell_id,
            receiver,
            target,
            actor,
            reason,
            true,
        )
        .await;
        assert!(
            matches!(refused, Err(DomainError::InvalidInput(_))),
            "{receiver} generation {target} actor {actor:?} reason {reason:?}: expected \
             InvalidInput, got {refused:?}"
        );
    }
    assert_eq!(
        member_state(&raw, &cell_id, 0).await,
        "required_placeholder"
    );
    assert_eq!(member_state(&raw, &cell_id, generation).await, "ready");
    assert_eq!(current_membership_version(&raw, &cell_id).await, version);

    namespace.release().await;
}

/// Hard-dead replacement: a generation that never checkpointed retires once a
/// strictly greater generation of the same receiver is ready.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn retire_generation_retires_a_dead_generation_once_a_greater_one_is_ready() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "retire-replaced").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = placed_cell(&raw, "DURABLE-x", 1).await;

    let version = current_membership_version(&raw, &cell_id).await;
    let MembershipCas::Applied {
        membership_generation: dead,
        ..
    } = membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version)
        .await
        .expect("join the generation that dies")
    else {
        panic!("join must apply");
    };
    assert_eq!(
        retire(&mut deadpool, &cell_id, "loreserver-1", dead).await,
        MembershipCas::RetirementUnproven
    );

    let successor = join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        1,
        12,
    )
    .await;
    assert!(successor > dead);

    let outcome = retire(&mut deadpool, &cell_id, "loreserver-1", dead).await;
    assert!(
        matches!(outcome, MembershipCas::Applied { membership_generation, .. } if membership_generation == dead),
        "expected Applied, got {outcome:?}"
    );
    assert_eq!(member_state(&raw, &cell_id, dead).await, "retired");
    assert_eq!(member_state(&raw, &cell_id, successor).await, "ready");
    assert_eq!(
        retirement_basis(&raw, &cell_id, "loreserver-1", dead)
            .await
            .as_deref(),
        Some("replacement"),
        "the hard-dead path needs no stop proof and records its own basis"
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// 3. Evaluator
// ---------------------------------------------------------------------------

/// Join and fully ready one receiver at `stream_identity`/`stream_epoch` with
/// a given frontier. Returns its generation.
async fn join_ready_receiver(
    raw: &Client,
    deadpool: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    stream_identity: &str,
    stream_epoch: i64,
    frontier: i64,
) -> i64 {
    let version = current_membership_version(raw, cell_id).await;
    let joined = membership::join_receiver(deadpool, cell_id, receiver_identity, version)
        .await
        .expect("join receiver");
    let MembershipCas::Applied {
        membership_generation: generation_id,
        ..
    } = joined
    else {
        panic!("unexpected {joined:?}");
    };
    let captured = CapturedPosition {
        stream_identity: stream_identity.to_string(),
        stream_epoch,
        start_sequence: 0,
    };
    membership::record_capture(raw, cell_id, receiver_identity, generation_id, &captured)
        .await
        .expect("record capture");
    membership::record_baseline(raw, cell_id, receiver_identity, generation_id)
        .await
        .expect("record baseline");
    let version = current_membership_version(raw, cell_id).await;
    let report = CheckpointReport {
        stream_identity: stream_identity.to_string(),
        stream_epoch,
        receiver_identity: receiver_identity.to_string(),
        membership_generation: generation_id,
        membership_version: version,
        contiguous_frontier: frontier,
        gaps: Vec::new(),
        poison: Vec::new(),
    };
    let outcome = report_checkpoint(deadpool, cell_id, &report)
        .await
        .expect("report checkpoint before readiness");
    assert_eq!(
        outcome,
        CheckpointOutcome::Applied {
            contiguous_frontier: frontier,
        }
    );
    let ready = membership::readiness_cas(deadpool, cell_id, receiver_identity, generation_id)
        .await
        .expect("readiness cas");
    assert!(
        matches!(ready, MembershipCas::Applied { .. }),
        "expected the receiver to become ready, got {ready:?}"
    );
    generation_id
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn events_at_or_below_the_minimum_required_frontier_become_consumer_safe_others_stay_accepted()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "eval-min").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-sfo3-cell-a";
    let stream_epoch = 8;

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");

    // The exact numbers from checkpoint-vector.json's
    // "all-required-members-past-the-sequence" case: two ready receivers at
    // frontiers 930 and 925, event broker_sequence 918 -- expected safe.
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-sfo3-cell-a-1",
        stream_identity,
        stream_epoch,
        930,
    )
    .await;
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-sfo3-cell-a-2",
        stream_identity,
        stream_epoch,
        925,
    )
    .await;

    let mut raw_mut = pg_client(&url).await;
    let repository_id = rand_repository_id();
    append_pending(&mut raw_mut, &cell_id, &repository_id, 1).await;
    let below_id =
        accept_one_via_relay(&raw, &mut deadpool, stream_identity, stream_epoch, 918).await;
    append_pending(&mut raw_mut, &cell_id, &repository_id, 2).await;
    let above_id =
        accept_one_via_relay(&raw, &mut deadpool, stream_identity, stream_epoch, 930).await;

    let outcome = evaluate_consumer_safe(&mut deadpool, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("evaluate consumer safety");
    assert_eq!(outcome.block, None, "unexpected block: {:?}", outcome.block);
    let proven = outcome.proven.expect("a proven safe vector");
    assert_eq!(proven.safe_sequence, 925, "the minimum of 930 and 925");
    assert_eq!(proven.required_members, 2);
    assert_eq!(outcome.advanced, 1, "only the row at or below 925 advances");

    assert_eq!(event_state(&raw, below_id).await, "consumer_safe");
    assert_eq!(event_state(&raw, above_id).await, "broker_accepted");

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn zero_required_members_never_reads_as_safe() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "eval-empty").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place, but join no receiver at all");

    let mut raw_mut = pg_client(&url).await;
    let repository_id = rand_repository_id();
    append_pending(&mut raw_mut, &cell_id, &repository_id, 1).await;
    let event_id =
        accept_one_via_relay(&raw, &mut deadpool, stream_identity, stream_epoch, 1).await;

    let outcome = evaluate_consumer_safe(&mut deadpool, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("evaluate consumer safety");
    assert_eq!(outcome.advanced, 0);
    assert_eq!(
        outcome.block,
        Some(EvaluationBlock::Membership(
            SafetyBlock::EmptyRequiredMembership
        ))
    );
    assert_eq!(event_state(&raw, event_id).await, "broker_accepted");

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_reset_in_progress_fence_blocks_consumer_safety_even_with_ready_members() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "eval-reset").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        stream_epoch,
        1000,
    )
    .await;

    let mut raw_mut = pg_client(&url).await;
    let repository_id = rand_repository_id();
    append_pending(&mut raw_mut, &cell_id, &repository_id, 1).await;
    let event_id =
        accept_one_via_relay(&raw, &mut deadpool, stream_identity, stream_epoch, 1).await;

    // Install a fence directly -- this is otherwise a fully-ready cell, so any
    // block here is attributable to the fence alone.
    install_reset_fence(&raw, &cell_id, stream_epoch, stream_epoch + 1).await;

    let outcome = evaluate_consumer_safe(&mut deadpool, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("evaluate consumer safety");
    assert_eq!(outcome.advanced, 0);
    assert_eq!(
        outcome.block,
        Some(EvaluationBlock::Membership(SafetyBlock::ResetInProgress))
    );
    assert_eq!(event_state(&raw, event_id).await, "broker_accepted");

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_evaluation_batch_bound_is_respected_over_2500_accepted_rows() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "eval-batch").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    // Frontier well above every seeded sequence, so every row is eligible and
    // the only thing limiting `advanced` per call is the batch bound itself.
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        stream_epoch,
        10_000,
    )
    .await;

    let mut seed_client = pg_client(&url).await;
    let repository_id = rand_repository_id();
    seed_broker_accepted_rows(
        &mut seed_client,
        &cell_id,
        &repository_id,
        stream_identity,
        stream_epoch,
        2_500,
    )
    .await;
    assert_eq!(
        count_by_state(&raw, &cell_id, stream_identity, "broker_accepted").await,
        2_500
    );

    // A caller-requested batch above MAX_EVALUATION_BATCH is clamped, not
    // rejected -- proving the clamp is real, not just the constant's value.
    let first = evaluate_consumer_safe(&mut deadpool, &cell_id, 1_500)
        .await
        .expect("first evaluation");
    assert_eq!(first.advanced, MAX_EVALUATION_BATCH as u64);

    let second = evaluate_consumer_safe(&mut deadpool, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("second evaluation");
    assert_eq!(second.advanced, MAX_EVALUATION_BATCH as u64);

    let third = evaluate_consumer_safe(&mut deadpool, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("third evaluation");
    assert_eq!(third.advanced, 500);

    assert_eq!(
        count_by_state(&raw, &cell_id, stream_identity, "consumer_safe").await,
        2_500
    );
    assert_eq!(
        count_by_state(&raw, &cell_id, stream_identity, "broker_accepted").await,
        0
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Fixture conformance: checkpoint-vector.json's frontier-versus-required-set
// arithmetic, driven from the fixture file on disk (not restated by hand).
// Fails on fixture drift within an existing sibling `lorehub` checkout;
// skips (with a loud notice) only when the sibling repo is absent entirely
// (a standalone checkout). See `common/fixture_resolution.rs`.
// ---------------------------------------------------------------------------

/// Loads and parses a fixture file for `test_name`. Returns `None` (after printing a loud skip
/// notice) when this is a standalone checkout with no sibling `lorehub` repo at all; panics on any
/// other failure (fixture drift within an existing sibling), per the fork-wide "must FAIL, never
/// skip" convention.
fn load_fixture(test_name: &str, name: &str) -> Option<Value> {
    let dir = match fixture_resolution::resolve_fixture_set_dir() {
        fixture_resolution::FixtureSetLocation::Directory(dir) => dir,
        fixture_resolution::FixtureSetLocation::Standalone { searched } => {
            fixture_resolution::print_standalone_skip_notice(test_name, &searched);
            return None;
        }
    };
    let path = dir.join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{name} fixture is required and must not be skipped when absent. Expected it at {}: \
             {error}",
            path.display()
        )
    });
    Some(
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}")),
    )
}

/// The fixture's "one-member-lags-below-the-sequence" case, driven from the
/// file on disk: two ready receivers at 930 and 910, event `broker_sequence`
/// 918, expected UNSAFE because the minimum (910) is below the sequence.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn one_lagging_member_from_the_fixture_file_blocks_the_whole_vector() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let Some(fixture) = load_fixture(
        "domain_outbox_checkpoints::one_lagging_member_from_the_fixture_file_blocks_the_whole_vector",
        "checkpoint-vector.json",
    ) else {
        return;
    };
    let cases = fixture["cases"].as_array().expect("cases array");
    let case = cases
        .iter()
        .find(|c| c["id"] == "one-member-lags-below-the-sequence")
        .expect("the fixture must still carry this case");
    let broker_sequence: i64 = case["event"]["broker_sequence"]
        .as_str()
        .expect("broker_sequence")
        .parse()
        .expect("broker_sequence parses as i64");
    let vector = case["vector"].as_array().expect("vector array");
    assert_eq!(vector.len(), 2, "the fixture case must name two members");
    let frontiers: Vec<i64> = vector
        .iter()
        .map(|m| {
            m["contiguous_frontier"]
                .as_str()
                .expect("contiguous_frontier")
                .parse()
                .expect("contiguous_frontier parses as i64")
        })
        .collect();
    let expected_safe = case["expected_consumer_safe"]
        .as_bool()
        .expect("expected_consumer_safe");
    assert!(!expected_safe, "sanity: this case must be the unsafe one");

    let namespace = CaseNamespace::acquire(&base_url, "fx-lag").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    for (i, frontier) in frontiers.iter().enumerate() {
        join_ready_receiver(
            &raw,
            &mut deadpool,
            &cell_id,
            &format!("receiver-{i}"),
            stream_identity,
            stream_epoch,
            *frontier,
        )
        .await;
    }

    let mut raw_mut = pg_client(&url).await;
    let repository_id = rand_repository_id();
    append_pending(&mut raw_mut, &cell_id, &repository_id, 1).await;
    let event_id = accept_one_via_relay(
        &raw,
        &mut deadpool,
        stream_identity,
        stream_epoch,
        broker_sequence,
    )
    .await;

    let outcome = evaluate_consumer_safe(&mut deadpool, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("evaluate consumer safety");
    assert_eq!(
        outcome.advanced, 0,
        "the fixture expects this row to stay unsafe"
    );
    let proven = outcome.proven.expect("membership itself was not blocked");
    assert_eq!(proven.safe_sequence, *frontiers.iter().min().unwrap());
    assert_eq!(event_state(&raw, event_id).await, "broker_accepted");

    namespace.release().await;
}
