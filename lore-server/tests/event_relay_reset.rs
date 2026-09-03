// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step C: the stream-reset receipt transaction and the cutover marker
//! that unblocks Step B's startup gate.
//!
//! # Scope of this file, and what it deliberately does not prove
//!
//! `lore_server::event_relay::reset_service::StreamResetHandler`'s own
//! `authenticate`/`authorize`/`validate_and_convert`/`build_ack` are already
//! pinned offline by `reset_service.rs`'s and `reset_wire.rs`'s own
//! `#[cfg(test)]` modules -- no Postgres, no gRPC, no TLS. Those cover the
//! wire-level security order (authenticate, then authorize, then derivation)
//! completely.
//!
//! `StreamResetHandler::receipt` (the method that actually calls
//! `reset::accept_reset` and the requeue) is a private inherent method, so it
//! is unreachable from this crate-external test binary; the only public entry
//! point is `report_stream_reset`, which requires an authenticated
//! `tonic::Request` carrying real mTLS peer certificates. `tonic::transport`'s
//! `TlsConnectInfo` has no public constructor outside a genuine TLS handshake
//! (its fields are private; only `Connected::connect_info()` on a live
//! `TlsStream` produces one), so exercising it here would mean standing up a
//! real rcgen-based mTLS loopback server -- a substantial harness this crate
//! has no precedent for and that duplicates no correctness surface beyond what
//! `reset_service.rs`'s offline tests already pin.
//!
//! This file instead proves the actual **receipt transaction** --
//! `lore_postgres::domain::outbox::reset::accept_reset`, the exact function
//! `StreamResetHandler::receipt` calls -- against real Postgres: generation
//! allocation, evidence persistence, requeue, byte-identical replay, and every
//! rejection class that can be driven without a live gRPC/mTLS stack. The
//! wire-level authentication/authorization gate is a call-order property
//! proven once, offline; this file proves the storage-side state machine that
//! sits behind it.
//!
//! If a full end-to-end mTLS loopback proof is wanted later, it needs a
//! dedicated rcgen-based harness (see `lore-transport/src/tls.rs` and
//! `grpc/server.rs`'s own certificate handling for the closest existing
//! patterns in this fork) -- flagged in the WP-119 Step C test report rather
//! than attempted here.

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::path::PathBuf;

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::AckInputs;
use lore_postgres::domain::outbox::CutoverOutcome;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::ResetAcceptance;
use lore_postgres::domain::outbox::ResetReport;
use lore_postgres::domain::outbox::accept_reset;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::relay;
use lore_postgres::domain::outbox::relay::BrokerAcceptanceRecord;
use lore_postgres::domain::outbox::reset::RESET_REASON_STREAM_EPOCH_ADVANCED;
use lore_postgres::domain::outbox::stamp_cutover;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_server::event_relay::StartupRefusal;
use lore_server::event_relay::enforce_startup_preconditions;
use lore_server::event_relay::reset_wire::DETECTION_ID_NAMESPACE;
use lore_server::event_relay::reset_wire::FINGERPRINT_DOMAIN;
use lore_server::event_relay::reset_wire::detection_id;
use lore_server::event_relay::reset_wire::reset_fingerprint;
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

/// `deadpool_postgres` is not a direct dependency of `lore-server`, so its
/// `Client` type is not nameable here -- only `lore_postgres::pool::Pool` is.
/// Every call site relies on type inference from `pool.get()` instead,
/// matching `event_relay_publish.rs`'s own convention.
async fn deadpool_pool(url: &str) -> lore_postgres::pool::Pool {
    ensure_schema_bootstrapped(url).await;
    build_pool(url, 8, &TlsConfig::default()).expect("build pool")
}

const TEST_CELL_ID: &str = "sfo3-cell-a";
const TEST_EMITTER: &str = "spiffe://commit0/ns/notification/sa/gateway-sfo3";

/// The exact `valid-epoch-advanced` vector from
/// `stream-reset-derivation.json`/`stream-reset-reports.json`: an ordinary
/// `STREAM_EPOCH_ADVANCED` successor, identity unchanged, epoch 7 -> 8.
fn epoch_advanced_report(placement_revision: i64) -> ResetReport {
    let fingerprint = reset_fingerprint(
        "sfo3-01:JS-9Q2F7K3M1X",
        TEST_CELL_ID,
        "DURABLE-sfo3-cell-a",
        7,
        "DURABLE-sfo3-cell-a",
        8,
    );
    ResetReport {
        detection_id: detection_id(&fingerprint),
        reset_fingerprint: fingerprint,
        broker_reset_identity: "sfo3-01:JS-9Q2F7K3M1X".to_string(),
        cell_id: TEST_CELL_ID.to_string(),
        placement_revision,
        old_stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        old_stream_epoch: 7,
        new_stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        new_stream_epoch: 8,
        reason_code: RESET_REASON_STREAM_EPOCH_ADVANCED,
        detected_at_unix_ms: 1_787_000_000_000,
    }
}

/// A minimal stand-in ack encoder. The real `StreamResetAckV1` wire encoding
/// is `reset_wire.rs`'s own responsibility and is pinned there byte-exactly;
/// this only needs SOME deterministic bytes to prove storage/replay
/// byte-identity.
fn test_ack(inputs: &AckInputs) -> Vec<u8> {
    format!(
        "ack:{}:{}:{}",
        inputs.cell_id, inputs.detection_id, inputs.reset_generation
    )
    .into_bytes()
}

async fn place_cell(raw: &Client, cell_id: &str, stream_identity: &str, stream_epoch: i64) {
    let state = membership::ensure_membership_state(raw, cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        raw,
        cell_id,
        stream_identity,
        stream_epoch,
        4,
        state.membership_version,
    )
    .await
    .expect("place the cell before a reset report can reference it");
}

fn rand_repository_id() -> [u8; 16] {
    rand::random()
}

fn rand_aggregate_id() -> [u8; 16] {
    rand::random()
}

async fn append_pending(client: &mut Client, cell_id: &str, repository_id: &[u8]) -> Uuid {
    let aggregate_id = rand_aggregate_id();
    let version = AggregateVersion::ordinal_only(1).encode();
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

// `accept_one`-shaped "move one pending row to broker_accepted" logic is
// inlined at its single call site rather than factored into a helper: it
// needs a `&mut deadpool_postgres::Client` parameter, and that type is not
// nameable in `lore-server` (see the `deadpool_pool` doc comment above).

async fn event_state(raw: &Client, event_id: Uuid) -> String {
    raw.query_one(
        "SELECT state FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("read event state")
    .get("state")
}

async fn reset_row_snapshot(raw: &Client, cell_id: &str) -> (i64, i64) {
    let row = raw
        .query_one(
            "SELECT membership_version, reset_generation FROM lore_outbox_membership_state \
             WHERE cell_id = $1",
            &[&cell_id],
        )
        .await
        .expect("read membership state row");
    (row.get("membership_version"), row.get("reset_generation"))
}

async fn reset_generation_row_count(raw: &Client, cell_id: &str) -> i64 {
    raw.query_one(
        "SELECT count(*) AS n FROM lore_outbox_reset_generations WHERE cell_id = $1",
        &[&cell_id],
    )
    .await
    .expect("count reset generations")
    .get("n")
}

// ---------------------------------------------------------------------------
// The receipt transaction
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_valid_first_report_allocates_the_next_generation_requeues_the_old_epoch_and_invalidates_readiness()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "reset-ok").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let pool = deadpool_pool(&url).await;
    let mut deadpool = pool.get().await.expect("checkout deadpool connection");

    place_cell(&raw, TEST_CELL_ID, "DURABLE-sfo3-cell-a", 7).await;

    let mut append_client = pg_client(&url).await;
    let repository_id = rand_repository_id();
    append_pending(&mut append_client, TEST_CELL_ID, &repository_id).await;

    // Move the appended row to `broker_accepted` at the OLD epoch, through
    // the real Step A claim/accept path -- inlined rather than a helper
    // because it needs a `&mut deadpool_postgres::Client`, whose type is not
    // nameable in `lore-server` (see `deadpool_pool`'s doc comment).
    let old_epoch_row = {
        let mut claimed = relay::claim_batch(
            &mut deadpool,
            "reset-test",
            10,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("claim the appended row");
        let claim = claimed.pop().expect("exactly one claimable row");
        let outcome = relay::record_broker_accepted(
            &raw,
            claim.event.event_id,
            claim.claim_generation,
            &BrokerAcceptanceRecord {
                stream_identity: "DURABLE-sfo3-cell-a".to_string(),
                stream_epoch: 7,
                broker_sequence: 918,
                gateway_response_id: "gw-918".to_string(),
                publisher_contract_version: 1,
            },
        )
        .await
        .expect("record broker acceptance");
        assert_eq!(outcome, relay::CasOutcome::Applied);
        claim.event.event_id
    };

    let report = epoch_advanced_report(4);
    let acceptance = accept_reset(&mut deadpool, &report, TEST_EMITTER, test_ack)
        .await
        .expect("accept_reset must not error on a valid first report");

    let ResetAcceptance::Accepted {
        stored,
        retired_generations: _,
        old_stream_identity,
        old_stream_epoch,
        ..
    } = acceptance
    else {
        panic!("expected Accepted, got {acceptance:?}");
    };
    assert_eq!(stored.reset_generation, 1, "first reset for a fresh cell");
    assert_eq!(old_stream_identity, "DURABLE-sfo3-cell-a");
    assert_eq!(old_stream_epoch, 7);
    assert_eq!(
        stored.ack_bytes,
        test_ack(&AckInputs {
            cell_id: TEST_CELL_ID.to_string(),
            detection_id: report.detection_id.clone(),
            reset_fingerprint: report.reset_fingerprint,
            reset_generation: stored.reset_generation,
            evidence_id: stored.evidence_id.clone(),
            persisted_at_unix_ms: 0, // not an input to test_ack
        })
    );

    // The caller (StreamResetHandler::receipt, in production) requeues the
    // retained unsafe rows for the old epoch before acknowledging.
    let requeued = relay::requeue_unsafe_for_epoch_reset(
        &mut deadpool,
        &old_stream_identity,
        old_stream_epoch,
    )
    .await
    .expect("requeue the old epoch's retained rows");
    assert_eq!(requeued, 1);
    assert_eq!(
        event_state(&raw, old_epoch_row).await,
        "pending",
        "the requeued row must return to pending with its original stable keys"
    );

    // Readiness invalidated: the snapshot is fenced and has no ready member.
    let snapshot = membership::read_membership_snapshot(&raw, TEST_CELL_ID)
        .await
        .expect("read snapshot")
        .expect("snapshot present");
    assert!(snapshot.reset_in_progress);
    assert!(snapshot.safety_block().is_some());

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn an_exact_replay_returns_the_byte_identical_ack_and_mutates_nothing_further() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "reset-replay").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let pool = deadpool_pool(&url).await;
    let mut deadpool = pool.get().await.expect("checkout deadpool connection");

    place_cell(&raw, TEST_CELL_ID, "DURABLE-sfo3-cell-a", 7).await;

    let report = epoch_advanced_report(4);
    let first = accept_reset(&mut deadpool, &report, TEST_EMITTER, test_ack)
        .await
        .expect("first accept");
    let ResetAcceptance::Accepted {
        stored: first_stored,
        ..
    } = first
    else {
        panic!("expected Accepted, got {first:?}");
    };

    // The commit succeeded and the placement has since moved (a later,
    // independent event); the retry -- differing only in detected_at, which
    // is excluded from duplicate equality -- must still return the original
    // stored ack rather than a placement-mismatch error.
    let after_first = reset_row_snapshot(&raw, TEST_CELL_ID).await;

    let mut retry = report.clone();
    retry.detected_at_unix_ms = 1_787_000_450_000;
    let second = accept_reset(&mut deadpool, &retry, TEST_EMITTER, test_ack)
        .await
        .expect("replay accept");
    let ResetAcceptance::Replayed {
        stored: second_stored,
    } = second
    else {
        panic!("expected Replayed, got {second:?}");
    };
    assert_eq!(second_stored.ack_bytes, first_stored.ack_bytes);
    assert_eq!(
        second_stored.reset_generation,
        first_stored.reset_generation
    );

    let after_replay = reset_row_snapshot(&raw, TEST_CELL_ID).await;
    assert_eq!(
        after_first, after_replay,
        "a replay must not allocate a second generation or mutate membership state"
    );
    assert_eq!(
        reset_generation_row_count(&raw, TEST_CELL_ID).await,
        1,
        "a replay must not insert a second reset_generations row"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_stale_old_epoch_is_rejected_and_mutates_nothing() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "reset-stale").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let pool = deadpool_pool(&url).await;
    let mut deadpool = pool.get().await.expect("checkout deadpool connection");

    // The cell's CURRENT old epoch is 8, but the report names 7 (stale).
    place_cell(&raw, TEST_CELL_ID, "DURABLE-sfo3-cell-a", 8).await;
    let before = reset_row_snapshot(&raw, TEST_CELL_ID).await;
    let before_count = reset_generation_row_count(&raw, TEST_CELL_ID).await;

    let report = epoch_advanced_report(4);
    let outcome = accept_reset(&mut deadpool, &report, TEST_EMITTER, test_ack)
        .await
        .expect("accept_reset call itself must not error");
    match outcome {
        ResetAcceptance::StaleOldStream {
            current_stream_identity,
            current_stream_epoch,
        } => {
            assert_eq!(
                current_stream_identity.as_deref(),
                Some("DURABLE-sfo3-cell-a")
            );
            assert_eq!(current_stream_epoch, Some(8));
        }
        other => panic!("expected StaleOldStream, got {other:?}"),
    }

    let after = reset_row_snapshot(&raw, TEST_CELL_ID).await;
    assert_eq!(before, after, "a stale report must mutate nothing");
    assert_eq!(
        reset_generation_row_count(&raw, TEST_CELL_ID).await,
        before_count
    );

    namespace.release().await;
}

/// The storage-layer analog of "mismatched cell": a report naming a cell with
/// no membership state at all (never placed, never cut over). The
/// authenticated-but-cross-cell case belongs to `reset_service.rs`'s own
/// offline `authorize` tests -- see the module docs.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_report_for_an_unknown_cell_is_rejected_and_mutates_nothing() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "reset-unknown").await;
    let url = namespace.pg_url().to_owned();
    // Schema bootstrapped (via `pg_client`'s side effect), but no membership
    // row is ever created for "sfo3-cell-z" -- it has never been through
    // cutover in this namespace.
    let raw = pg_client(&url).await;
    let pool = deadpool_pool(&url).await;
    let mut deadpool = pool.get().await.expect("checkout deadpool connection");

    let fingerprint = reset_fingerprint(
        "sfo3-01:JS-unknown",
        "sfo3-cell-z",
        "DURABLE-sfo3-cell-z",
        1,
        "DURABLE-sfo3-cell-z",
        2,
    );
    let report = ResetReport {
        detection_id: detection_id(&fingerprint),
        reset_fingerprint: fingerprint,
        broker_reset_identity: "sfo3-01:JS-unknown".to_string(),
        cell_id: "sfo3-cell-z".to_string(),
        placement_revision: 0,
        old_stream_identity: "DURABLE-sfo3-cell-z".to_string(),
        old_stream_epoch: 1,
        new_stream_identity: "DURABLE-sfo3-cell-z".to_string(),
        new_stream_epoch: 2,
        reason_code: RESET_REASON_STREAM_EPOCH_ADVANCED,
        detected_at_unix_ms: 1_787_000_000_000,
    };

    let outcome = accept_reset(&mut deadpool, &report, TEST_EMITTER, test_ack)
        .await
        .expect("accept_reset call itself must not error");
    assert_eq!(outcome, ResetAcceptance::CellUnknown);
    assert_eq!(reset_generation_row_count(&raw, "sfo3-cell-z").await, 0);

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Derivation fixture conformance -- pure, no Postgres. Fails if the fixture is
// absent rather than skipping, per the fork-wide convention.
// ---------------------------------------------------------------------------

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lorehub/docs/contracts/fixtures/lore-notification-plane")
        .join(name)
}

fn load_fixture(name: &str) -> Value {
    let path = fixture_path(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{name} fixture is required and must not be skipped when absent. Expected it at {}: \
             {error}",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}"))
}

#[test]
fn every_vector_in_the_stream_reset_derivation_fixture_file_reproduces() {
    let fixture = load_fixture("stream-reset-derivation.json");

    let pins = &fixture["contract_pins"];
    assert_eq!(
        pins["domain_prefix_ascii"]["value"].as_str().unwrap(),
        std::str::from_utf8(&FINGERPRINT_DOMAIN[..FINGERPRINT_DOMAIN.len() - 1]).unwrap(),
        "the wire module's domain prefix drifted from the pinned fixture value"
    );
    assert_eq!(*FINGERPRINT_DOMAIN.last().unwrap(), 0x00);
    assert_eq!(
        pins["detection_id_namespace"]["value"].as_str().unwrap(),
        DETECTION_ID_NAMESPACE.hyphenated().to_string(),
        "the wire module's UUIDv5 namespace drifted from the pinned fixture value"
    );

    let vectors = fixture["vectors"].as_array().expect("vectors array");
    assert!(
        !vectors.is_empty(),
        "the fixture must carry at least one vector"
    );
    for vector in vectors {
        let id = vector["id"].as_str().expect("id");
        let inputs = &vector["inputs"];
        let broker_reset_identity = inputs["broker_reset_identity"].as_str().unwrap();
        let cell_id = inputs["cell_id"].as_str().unwrap();
        let old_stream_identity = inputs["old_stream_identity"].as_str().unwrap();
        let old_stream_epoch: u64 = inputs["old_stream_epoch"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let new_stream_identity = inputs["new_stream_identity"].as_str().unwrap();
        let new_stream_epoch: u64 = inputs["new_stream_epoch"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let expected_fingerprint_hex = vector["reset_fingerprint_hex"].as_str().unwrap();
        let expected_detection_id = vector["detection_id"].as_str().unwrap();
        let expected_preimage_hex = vector["preimage_hex"].as_str().unwrap();
        let expected_preimage_len = vector["preimage_byte_length"].as_u64().unwrap() as usize;

        let preimage = lore_server::event_relay::reset_wire::fingerprint_preimage(
            broker_reset_identity,
            cell_id,
            old_stream_identity,
            old_stream_epoch,
            new_stream_identity,
            new_stream_epoch,
        );
        assert_eq!(
            preimage.len(),
            expected_preimage_len,
            "{id}: preimage length"
        );
        let preimage_hex: String = preimage.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(preimage_hex, expected_preimage_hex, "{id}: preimage bytes");

        let fingerprint = reset_fingerprint(
            broker_reset_identity,
            cell_id,
            old_stream_identity,
            old_stream_epoch,
            new_stream_identity,
            new_stream_epoch,
        );
        let fingerprint_hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            fingerprint_hex, expected_fingerprint_hex,
            "{id}: fingerprint"
        );
        assert_eq!(
            detection_id(&fingerprint),
            expected_detection_id,
            "{id}: detection_id"
        );
    }
}

// ---------------------------------------------------------------------------
// Cutover stamp -- the key to Step B's fail-closed startup gate
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn stamping_cutover_makes_step_bs_startup_gate_pass_and_is_idempotent() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "cutover").await;
    let url = namespace.pg_url().to_owned();
    let domain = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let raw = pg_client(&url).await;
    let pool = build_pool(&url, 2, &TlsConfig::default()).expect("build pool for startup check");

    // Before stamping, the startup gate refuses -- the same assertion
    // `event_relay_wiring.rs`'s own `startup_fails_when_cutover_has_not_been_stamped`
    // makes via raw SQL absence, reused here as the baseline this test's
    // `stamp_cutover` call is expected to flip.
    let before = enforce_startup_preconditions(&pool, &domain).await;
    assert!(
        matches!(before, Err(StartupRefusal::CutoverIncomplete)),
        "expected CutoverIncomplete before stamping, got {before:?}"
    );

    let stamped = stamp_cutover(&raw, "sfo3-cell-a")
        .await
        .expect("stamp cutover");
    let CutoverOutcome::Stamped {
        cutover_at: first_stamp,
    } = stamped
    else {
        panic!("expected Stamped, got {stamped:?}");
    };

    let after = enforce_startup_preconditions(&pool, &domain)
        .await
        .expect("startup must succeed once cutover is stamped");
    assert!(after.cutover_at.is_some());

    // Idempotent: a second stamp reports the ORIGINAL timestamp, not a new
    // one, so an operator's incident correlation is never invalidated by a
    // retried command.
    let again = stamp_cutover(&raw, "sfo3-cell-a")
        .await
        .expect("stamp cutover again");
    let CutoverOutcome::AlreadyStamped {
        cutover_at: second_stamp,
    } = again
    else {
        panic!("expected AlreadyStamped, got {again:?}");
    };
    assert_eq!(first_stamp, second_stamp);

    namespace.release().await;
}
