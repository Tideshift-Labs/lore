// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Contract amendment A-32's offline event-plane switch
//! (`lore-postgres/src/domain/outbox/event_plane.rs`): `set_event_plane`'s
//! transactional move-to-evidence, its contention refusals, and
//! `read_boot_facts`'s marker/row-presence read.
//!
//! This file proves the **store-level mechanics** against a real database:
//! the pure resolution matrix (`[notification] event_plane` parsing,
//! `outbox_production_enabled`, `check_marker`) is already proven by
//! `event_plane.rs`'s and `lore-server/src/event_relay/plane.rs`'s own
//! `#[cfg(test)]` modules and is not re-derived here.
//!
//! # What this file deliberately does not prove
//!
//! Whether every CR-032 producer site actually calls
//! `DomainContext::outbox_cell_id()` (and so appends zero rows under
//! `live_only`) is a `lore-server` fact, not a `lore-postgres` one -- proven
//! there by `event_relay::plane`'s `only_live_only_stops_outbox_production`
//! plus a static sweep of every call site (`domain.rs`, `lock_service.rs`,
//! and six `grpc/**` handlers all read `outbox_cell_id()`, never `cell_id()`,
//! for an event decision). A live, end-to-end governed-mutation proof that
//! `live_only` yields zero outbox rows through the real `DomainContext` /
//! `Governed*` wrapper types is not attempted here: it would require
//! reproducing `p12_live.rs`'s repository-create/delete scaffolding (receipt
//! prepare, canonical-intent digest, authorization admission) for marginal
//! additional proof over the already-uniform call-site sweep. Flagged as a
//! gap for a follow-up `lore-server` live case, not silently dropped.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset (matches
//! `domain_outbox_producers.rs`'s own convention). Each case gets a fresh
//! database from its runner, `run-event-plane-live.ps1`, so no case shares
//! state with another.

use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::event_plane;
use lore_postgres::domain::outbox::event_plane::EventPlane;
use lore_postgres::domain::outbox::event_plane::SetEventPlaneOutcome;
use lore_postgres::domain::outbox::relay::BrokerAcceptanceRecord;
use lore_postgres::domain::outbox::relay::CasOutcome;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_postgres::domain::outbox::relay::record_broker_accepted;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

/// Connect and install every schema the boot path would, including
/// `EVENT_PLANE_SCHEMA` (`PostgresDomainStore::connect` runs it).
async fn store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

async fn raw_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect raw assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("raw postgres connection error: {e}");
        }
    });
    client
}

async fn deadpool_client(url: &str) -> lore_postgres::pool::Client {
    let pool = build_pool(url, 4, &TlsConfig::default()).expect("build deadpool pool");
    pool.get().await.expect("checkout deadpool connection")
}

/// This database's current `pg_stat_database.numbackends`, read through a
/// connection the caller keeps open for the rest of the case.
///
/// `set_event_plane`'s own `own_backends` parameter has no way to introspect
/// how many connections a caller's pool or earlier setup already holds, so
/// every case below measures this on its own persistent `observer`
/// connection immediately before opening the deadpool client that will
/// perform the switch, and passes `baseline + 1` (the `+ 1` for that
/// soon-to-be-opened client). That makes every case's own leftover
/// connections (the schema-install pool, setup clients kept open for
/// post-switch assertions) count as "mine" regardless of exactly how many
/// there are, and isolates each case's *intentional* extra session -- opened
/// either before or after this measurement, by design -- as the only
/// uncounted backend.
///
/// The `observer` must be a connection the caller does not drop before the
/// switch call: an earlier version of this helper opened and immediately
/// dropped its own throwaway connection, which raced its own disconnect
/// against `other`/`locker` connecting in the cases below and made the
/// count agree by coincidence rather than by measurement.
async fn total_backends(observer: &Client) -> i64 {
    observer
        .query_one(
            "SELECT numbackends::bigint FROM pg_catalog.pg_stat_database \
              WHERE datname = pg_catalog.current_database()",
            &[],
        )
        .await
        .expect("numbackends query")
        .get(0)
}

fn rand_cell_id() -> String {
    format!("cell-{:016x}", rand::random::<u64>())
}

fn rand_repository_id() -> [u8; 16] {
    rand::random()
}

/// Append one pending row and return its event ID.
async fn append_pending(client: &mut Client, cell_id: &str, repository_id: &[u8]) -> Uuid {
    let version = AggregateVersion::ordinal_only(1).encode();
    let aggregate_id: [u8; 16] = rand::random();
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
        payload: b"{\"k\":\"v\"}",
    };
    let appended = append(&tx, &event).await.expect("append pending event");
    tx.commit().await.expect("commit append");
    appended.event_id
}

/// Claim and record broker acceptance for one pending row, so it moves to
/// `broker_accepted`.
async fn accept(
    raw: &Client,
    pool_client: &mut lore_postgres::pool::Client,
    event_id: Uuid,
) -> BrokerAcceptanceRecord {
    let claimed = claim_batch(
        pool_client,
        &format!("worker-{:016x}", rand::random::<u64>()),
        50,
        Duration::from_secs(30),
    )
    .await
    .expect("claim");
    let claim = claimed
        .iter()
        .find(|c| c.event.event_id == event_id)
        .unwrap_or_else(|| panic!("{event_id} was not among the claimed rows"));
    let acceptance = BrokerAcceptanceRecord {
        stream_identity: format!("stream-{:08x}", rand::random::<u32>()),
        stream_epoch: 1,
        broker_sequence: 1,
        gateway_response_id: format!("resp-{:016x}", rand::random::<u64>()),
        publisher_contract_version: 1,
    };
    let outcome = record_broker_accepted(raw, event_id, claim.claim_generation, &acceptance)
        .await
        .expect("record broker acceptance");
    assert_eq!(outcome, CasOutcome::Applied);
    acceptance
}

/// Move an already-`broker_accepted` row straight to `consumer_safe`.
///
/// A real promotion goes through the membership/checkpoint evaluator
/// (`evaluate_consumer_safe`), which this file does not stand up -- what
/// `set_event_plane` cares about is the stored `state` column alone (its
/// retire query matches `state IN ('broker_accepted', 'consumer_safe')`), so
/// a direct update proves the same retirement path without that machinery.
async fn force_consumer_safe(raw: &Client, event_id: Uuid) {
    let updated = raw
        .execute(
            "UPDATE lore_outbox_events SET state = 'consumer_safe' WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("force consumer_safe");
    assert_eq!(updated, 1);
}

async fn event_state(raw: &Client, event_id: Uuid) -> Option<String> {
    raw.query_opt(
        "SELECT state FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("event state query")
    .map(|r| r.get("state"))
}

async fn transition_count(raw: &Client, cell_id: &str) -> i64 {
    raw.query_one(
        "SELECT count(*) FROM lore_outbox_event_plane_transitions WHERE cell_id = $1",
        &[&cell_id],
    )
    .await
    .expect("transition count query")
    .get(0)
}

/// One retired row's evidence columns, for the verbatim comparison.
struct RetiredRow {
    transition_seq: i64,
    idempotency_key: Vec<u8>,
    repository_id: Vec<u8>,
    repository_generation: i64,
    event_kind: String,
    aggregate_kind: String,
    aggregate_id: Vec<u8>,
    aggregate_version: Vec<u8>,
    payload: Vec<u8>,
    state_at_retirement: String,
    stream_identity: Option<String>,
    stream_epoch: Option<i64>,
    broker_sequence: Option<i64>,
    gateway_response_id: Option<String>,
    disposition: String,
    disposition_actor: String,
    disposition_reason: String,
}

async fn retired_row(raw: &Client, event_id: Uuid) -> RetiredRow {
    let row = raw
        .query_one(
            "SELECT transition_seq, idempotency_key, repository_id, repository_generation, \
                    event_kind, aggregate_kind, aggregate_id, aggregate_version, payload, \
                    state_at_retirement, stream_identity, stream_epoch, broker_sequence, \
                    gateway_response_id, disposition, disposition_actor, disposition_reason \
               FROM lore_outbox_retired_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("retired row query");
    RetiredRow {
        transition_seq: row.get("transition_seq"),
        idempotency_key: row.get("idempotency_key"),
        repository_id: row.get("repository_id"),
        repository_generation: row.get("repository_generation"),
        event_kind: row.get("event_kind"),
        aggregate_kind: row.get("aggregate_kind"),
        aggregate_id: row.get("aggregate_id"),
        aggregate_version: row.get("aggregate_version"),
        payload: row.get("payload"),
        state_at_retirement: row.get("state_at_retirement"),
        stream_identity: row.get("stream_identity"),
        stream_epoch: row.get("stream_epoch"),
        broker_sequence: row.get("broker_sequence"),
        gateway_response_id: row.get("gateway_response_id"),
        disposition: row.get("disposition"),
        disposition_actor: row.get("disposition_actor"),
        disposition_reason: row.get("disposition_reason"),
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn switching_to_live_only_refuses_while_a_pending_row_exists() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let mut raw = raw_client(&url).await;
    let event_id = append_pending(&mut raw, &cell_id, &repository_id).await;

    let baseline = total_backends(&raw).await;
    let mut client = deadpool_client(&url).await;
    let result = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "test-actor",
        "pending row must block",
        baseline + 1,
    )
    .await;

    assert!(
        matches!(result, Err(DomainError::NotReady(_))),
        "expected NotReady, got {result:?}"
    );
    assert_eq!(
        event_state(&raw, event_id).await.as_deref(),
        Some("pending"),
        "the pending row must be untouched"
    );
    assert_eq!(
        transition_count(&raw, &cell_id).await,
        0,
        "a refused switch must write no transition row"
    );
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn switching_to_live_only_moves_broker_accepted_and_consumer_safe_rows_verbatim_with_audit() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let raw = raw_client(&url).await;
    let mut raw_mut = raw_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let accepted_id = append_pending(&mut raw_mut, &cell_id, &repository_id).await;
    let accepted_acceptance = accept(&raw, &mut pool_client, accepted_id).await;

    let safe_id = append_pending(&mut raw_mut, &cell_id, &repository_id).await;
    let safe_acceptance = accept(&raw, &mut pool_client, safe_id).await;
    force_consumer_safe(&raw, safe_id).await;

    let idempotency_before: [(Uuid, Vec<u8>); 2] = [
        (
            accepted_id,
            raw.query_one(
                "SELECT idempotency_key FROM lore_outbox_events WHERE event_id = $1",
                &[&accepted_id],
            )
            .await
            .expect("idempotency key before")
            .get(0),
        ),
        (
            safe_id,
            raw.query_one(
                "SELECT idempotency_key FROM lore_outbox_events WHERE event_id = $1",
                &[&safe_id],
            )
            .await
            .expect("idempotency key before")
            .get(0),
        ),
    ];

    let baseline = total_backends(&raw).await;
    let mut switch_client = deadpool_client(&url).await;
    let outcome = event_plane::set_event_plane(
        &mut switch_client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "planned live_only rollout",
        baseline + 1,
    )
    .await
    .expect("switch to live_only must succeed with no pending rows");

    let SetEventPlaneOutcome::Applied {
        from,
        to,
        transition_seq,
        retired_rows,
        ..
    } = outcome
    else {
        panic!("expected Applied, got {outcome:?}");
    };
    assert_eq!(from, EventPlane::Durable);
    assert_eq!(to, EventPlane::LiveOnly);
    assert_eq!(transition_seq, 1);
    assert_eq!(retired_rows, 2);

    // Nothing left live.
    assert_eq!(event_state(&raw, accepted_id).await, None);
    assert_eq!(event_state(&raw, safe_id).await, None);

    // Every field the switch is documented to carry verbatim, for both rows.
    for (event_id, expected_state, acceptance, (_, idempotency)) in [
        (
            accepted_id,
            "broker_accepted",
            &accepted_acceptance,
            &idempotency_before[0],
        ),
        (
            safe_id,
            "consumer_safe",
            &safe_acceptance,
            &idempotency_before[1],
        ),
    ] {
        let retired = retired_row(&raw, event_id).await;
        assert_eq!(retired.transition_seq, 1);
        assert_eq!(&retired.idempotency_key, idempotency);
        assert_eq!(retired.repository_id, repository_id);
        assert_eq!(retired.repository_generation, 1);
        assert_eq!(retired.event_kind, "branch.pushed");
        assert_eq!(retired.aggregate_kind, "branch");
        assert_eq!(retired.aggregate_id.len(), 16);
        assert_eq!(
            retired.aggregate_version,
            AggregateVersion::ordinal_only(1).encode()
        );
        assert_eq!(retired.payload, b"{\"k\":\"v\"}");
        assert_eq!(retired.state_at_retirement, expected_state);
        assert_eq!(
            retired.stream_identity.as_deref(),
            Some(acceptance.stream_identity.as_str())
        );
        assert_eq!(retired.stream_epoch, Some(acceptance.stream_epoch));
        assert_eq!(retired.broker_sequence, Some(acceptance.broker_sequence));
        assert_eq!(
            retired.gateway_response_id.as_deref(),
            Some(acceptance.gateway_response_id.as_str())
        );
        assert_eq!(retired.disposition, "retired_live_only");
        assert_eq!(retired.disposition_actor, "operator-a");
        assert_eq!(retired.disposition_reason, "planned live_only rollout");
    }

    let transition = raw
        .query_one(
            "SELECT from_plane, to_plane, actor, reason, retired_rows \
               FROM lore_outbox_event_plane_transitions WHERE cell_id = $1 AND transition_seq = 1",
            &[&cell_id],
        )
        .await
        .expect("transition row query");
    let from_plane: String = transition.get("from_plane");
    let to_plane: String = transition.get("to_plane");
    let actor: String = transition.get("actor");
    let reason: String = transition.get("reason");
    let retired_rows_col: i64 = transition.get("retired_rows");
    assert_eq!(from_plane, "durable");
    assert_eq!(to_plane, "live_only");
    assert_eq!(actor, "operator-a");
    assert_eq!(reason, "planned live_only rollout");
    assert_eq!(retired_rows_col, 2);
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn rerunning_an_applied_switch_reports_already_current() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let observer = raw_client(&url).await;

    // One client, reused for both calls: its connection stays counted as
    // "mine" throughout, so `own_backends` needs measuring only once.
    let baseline = total_backends(&observer).await;
    let mut client = deadpool_client(&url).await;
    let own_backends = baseline + 1;
    let first = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "first switch, no rows to retire",
        own_backends,
    )
    .await
    .expect("first switch must succeed");
    assert!(matches!(first, SetEventPlaneOutcome::Applied { .. }));

    let second = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-b",
        "rerun after a lost commit reply",
        own_backends,
    )
    .await
    .expect("rerun must not error");
    assert_eq!(
        second,
        SetEventPlaneOutcome::AlreadyCurrent {
            plane: EventPlane::LiveOnly
        }
    );

    let raw = raw_client(&url).await;
    assert_eq!(
        transition_count(&raw, &cell_id).await,
        1,
        "the rerun must write no second transition row"
    );
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn switching_back_to_durable_carries_a_stray_pending_row_and_restarts_its_age() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();

    // Opened before the baseline measurement below, so it stays counted as
    // "mine" for both switch calls even though the row it appends comes
    // later.
    let mut raw = raw_client(&url).await;

    let baseline = total_backends(&raw).await;
    let mut client = deadpool_client(&url).await;
    let own_backends = baseline + 1;
    let to_live_only = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "no rows yet",
        own_backends,
    )
    .await
    .expect("switch to live_only with no rows must succeed");
    assert!(matches!(to_live_only, SetEventPlaneOutcome::Applied { .. }));

    // A live_only cell should never gain a row through ordinary production
    // (that predicate lives in `lore-server`), so this simulates the one way
    // one could appear anyway: a direct write, standing in for a defect. A
    // live_only boot refuses it, and `set-plane durable` is the supported exit.
    let stray = append_pending(&mut raw, &cell_id, &repository_id).await;
    raw.execute(
        "UPDATE lore_outbox_events SET unpublished_since = clock_timestamp() - interval '1 hour' \
          WHERE event_id = $1",
        &[&stray],
    )
    .await
    .expect("age the stray row");

    let outcome = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::Durable,
        "operator-b",
        "resume durable mode to publish a stray row",
        own_backends,
    )
    .await
    .expect("durable re-entry carries a stray pending row");
    let SetEventPlaneOutcome::Applied {
        carried_pending_rows,
        retired_rows,
        ..
    } = outcome
    else {
        panic!("expected Applied, got {outcome:?}");
    };
    assert_eq!(carried_pending_rows, 1);
    let audited: i64 = raw
        .query_one(
            "SELECT carried_pending_rows FROM lore_outbox_event_plane_transitions \
              WHERE cell_id = $1 AND to_plane = 'durable'",
            &[&cell_id],
        )
        .await
        .expect("re-entry transition")
        .get(0);
    assert_eq!(audited, 1, "the transition row records the carried row");
    assert_eq!(retired_rows, 0);
    assert_eq!(
        event_state(&raw, stray).await.as_deref(),
        Some("pending"),
        "the carried row stays pending for the relay to publish"
    );
    let age: f64 = raw
        .query_one(
            "SELECT extract(epoch FROM clock_timestamp() - unpublished_since)::float8 \
               FROM lore_outbox_events WHERE event_id = $1",
            &[&stray],
        )
        .await
        .expect("carried row age")
        .get(0);
    assert!(
        age < 60.0,
        "re-entry must restart the carried row's publication clock, or admission reads an \
         hour-old backlog; age was {age}s"
    );
    assert_eq!(transition_count(&raw, &cell_id).await, 2);
}

/// Insert one parked dead letter for `cell_id` directly: the relay's own
/// dead-letter path needs a claim and a terminal publish result, and what the
/// switch and the requeue guard read is the parked row alone.
async fn park_dead_letter(raw: &Client, cell_id: &str) -> Uuid {
    let event_id = Uuid::new_v4();
    let key: [u8; 32] = rand::random();
    let repository_id = rand_repository_id();
    let aggregate_id: [u8; 16] = rand::random();
    let version = AggregateVersion::ordinal_only(1).encode();
    raw.execute(
        "INSERT INTO lore_outbox_dead_letters \
             (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
              event_kind, aggregate_kind, aggregate_id, aggregate_version, \
              payload_schema_version, payload, created_at, attempt_count, terminal_class, \
              first_failed_at, last_failed_at, disposition) \
         VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '\\x7b7d', \
                 clock_timestamp(), 1, 'UNSUPPORTED_SCHEMA', clock_timestamp(), \
                 clock_timestamp(), 'parked')",
        &[
            &event_id,
            &cell_id,
            &key.as_slice(),
            &repository_id.as_slice(),
            &aggregate_id.as_slice(),
            &version.as_slice(),
        ],
    )
    .await
    .expect("park a dead letter");
    event_id
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn switching_to_live_only_refuses_while_a_parked_dead_letter_exists() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let raw = raw_client(&url).await;
    park_dead_letter(&raw, &cell_id).await;

    let baseline = total_backends(&raw).await;
    let mut client = deadpool_client(&url).await;
    let result = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "go live_only",
        baseline + 1,
    )
    .await;
    let Err(DomainError::NotReady(message)) = result else {
        panic!("expected NotReady, got {result:?}");
    };
    assert!(message.contains("parked dead letter"), "{message}");
    assert!(message.contains("requeue-dead-letter"), "{message}");
    assert!(message.contains("obsolete"), "{message}");
    assert_eq!(transition_count(&raw, &cell_id).await, 0);
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn requeue_and_replay_refuse_on_a_live_only_cell() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let raw = raw_client(&url).await;
    let baseline = total_backends(&raw).await;
    let mut client = deadpool_client(&url).await;
    event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "go live_only",
        baseline + 1,
    )
    .await
    .expect("switch an empty cell to live_only");
    // A dead letter that predates nothing: inserted after the switch, standing
    // in for any path that leaves one on a live_only cell.
    let dead = park_dead_letter(&raw, &cell_id).await;

    let requeue = lore_postgres::domain::outbox::operator::requeue_dead_letter(
        &mut client,
        &cell_id,
        dead,
        "operator-b",
        "retry",
    )
    .await;
    let Err(DomainError::NotReady(message)) = requeue else {
        panic!("expected NotReady from requeue, got {requeue:?}");
    };
    assert!(message.contains("set-plane durable"), "{message}");
    assert_eq!(
        event_state(&raw, dead).await,
        None,
        "no pending row was written"
    );

    let replay = lore_postgres::domain::outbox::operator::replay(
        &mut client,
        &cell_id,
        None,
        Duration::from_secs(3600),
        10,
        "operator-b",
        "replay",
    )
    .await;
    assert!(
        matches!(replay, Err(DomainError::NotReady(_))),
        "expected NotReady from replay, got {replay:?}"
    );
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn durable_re_entry_retires_every_live_receiver_generation_with_audit() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let raw = raw_client(&url).await;
    raw.batch_execute(&format!(
        "INSERT INTO lore_outbox_membership_state \
             (cell_id, membership_version, next_membership_generation, reset_generation, \
              current_placement_revision, updated_at) \
         VALUES ('{cell_id}', 3, 3, 0, 0, clock_timestamp()); \
         INSERT INTO lore_outbox_receiver_membership \
             (cell_id, receiver_identity, membership_generation, membership_version, state, \
              created_at, updated_at) \
         VALUES ('{cell_id}', 'replica-1', 1, 2, 'joining', clock_timestamp(), clock_timestamp()), \
                ('{cell_id}', 'replica-2', 2, 3, 'joining', clock_timestamp(), clock_timestamp());"
    ))
    .await
    .expect("seed receiver membership");

    let baseline = total_backends(&raw).await;
    let mut client = deadpool_client(&url).await;
    for (target, reason) in [
        (EventPlane::LiveOnly, "leave durable"),
        (EventPlane::Durable, "re-enter durable"),
    ] {
        event_plane::set_event_plane(
            &mut client,
            &cell_id,
            target,
            "operator",
            reason,
            baseline + 1,
        )
        .await
        .unwrap_or_else(|e| panic!("switch to {target} failed: {e:?}"));
    }

    let live: i64 = raw
        .query_one(
            "SELECT count(*) FROM lore_outbox_receiver_membership \
              WHERE cell_id = $1 AND state <> 'retired'",
            &[&cell_id],
        )
        .await
        .expect("live members")
        .get(0);
    assert_eq!(
        live, 0,
        "re-entry must leave no stale generation in the required set"
    );
    let (version, audited): (i64, i64) = {
        let state = raw
            .query_one(
                "SELECT membership_version FROM lore_outbox_membership_state WHERE cell_id = $1",
                &[&cell_id],
            )
            .await
            .expect("membership state");
        let audit = raw
            .query_one(
                "SELECT retired_generations FROM lore_outbox_event_plane_transitions \
                  WHERE cell_id = $1 AND to_plane = 'durable'",
                &[&cell_id],
            )
            .await
            .expect("re-entry transition");
        (state.get(0), audit.get(0))
    };
    assert_eq!(
        version, 4,
        "one membership-version bump anchors the retirement"
    );
    assert_eq!(
        audited, 2,
        "the transition row records how many generations it retired"
    );
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn durable_re_entry_refuses_while_a_reset_fence_is_in_progress() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let raw = raw_client(&url).await;
    let baseline = total_backends(&raw).await;
    let mut client = deadpool_client(&url).await;
    event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator",
        "leave durable",
        baseline + 1,
    )
    .await
    .expect("switch to live_only");
    let fingerprint: [u8; 32] = rand::random();
    raw.execute(
        "INSERT INTO lore_outbox_reset_generations \
             (cell_id, reset_generation, detection_id, reset_fingerprint, broker_reset_identity, \
              old_stream_identity, old_stream_epoch, new_stream_identity, new_stream_epoch, \
              reason_code, placement_revision, detected_at_unix_ms, emitter_identity, \
              evidence_id, ack_bytes, state, persisted_at) \
         VALUES ($1, 1, 'detection-1', $2, 'broker-1', 'stream-a', 1, 'stream-b', 2, 1, 0, 0, \
                 'emitter', 'evidence-1', '\\x01', 'reset_in_progress', clock_timestamp())",
        &[&cell_id, &fingerprint.as_slice()],
    )
    .await
    .expect("open a reset fence");

    let result = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::Durable,
        "operator",
        "re-enter durable",
        baseline + 1,
    )
    .await;
    let Err(DomainError::NotReady(message)) = result else {
        panic!("expected NotReady, got {result:?}");
    };
    assert!(message.contains("stream-reset fence"), "{message}");
    assert_eq!(transition_count(&raw, &cell_id).await, 1);
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn a_second_connected_backend_refuses_the_switch_until_it_disconnects() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();
    let observer = raw_client(&url).await;

    // Measured before `other` connects, so `other` is the one uncounted
    // extra backend below -- whatever this test's own setup already holds is
    // folded into `baseline` regardless of how many connections that is.
    let baseline = total_backends(&observer).await;

    // A second, otherwise-idle session to this database, not folded into
    // `own_backends` below: it alone must be enough to prove the refusal.
    let other = raw_client(&url).await;
    other
        .simple_query("SELECT 1")
        .await
        .expect("prove the other session is live");

    let mut client = deadpool_client(&url).await;
    let refused = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "should be refused while another session is connected",
        baseline + 1,
    )
    .await;
    assert!(
        matches!(refused, Err(DomainError::Contention(_))),
        "expected Contention, got {refused:?}"
    );

    drop(other);
    // The bounded settle wait inside `set_event_plane` itself already
    // retries; a fresh call after the connection is fully gone must succeed.
    let retry_baseline = total_backends(&observer).await;
    let mut retry_client = deadpool_client(&url).await;
    let applied = event_plane::set_event_plane(
        &mut retry_client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "retry once the other session is gone",
        retry_baseline + 1,
    )
    .await
    .expect("the retry must succeed once the other session has disconnected");
    assert!(matches!(applied, SetEventPlaneOutcome::Applied { .. }));
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn a_held_table_lock_refuses_the_switch_even_when_backend_count_passes() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let _store = store(&url).await;
    let cell_id = rand_cell_id();

    // A concurrent session that holds one of the three tables the switch
    // locks in ACCESS EXCLUSIVE mode.
    let mut locker = raw_client(&url).await;
    let lock_tx = locker.transaction().await.expect("begin lock tx");
    lock_tx
        .batch_execute("LOCK TABLE lore_outbox_events IN ACCESS SHARE MODE")
        .await
        .expect("hold a conflicting lock");

    // A connection distinct from `locker`, whose own transaction is mid-lock
    // and therefore unavailable to query with. Measured with `locker`
    // already connected and holding its lock, so it is folded into "mine"
    // below on purpose: the numbackends gate must pass, isolating the
    // refusal to the ACCESS EXCLUSIVE NOWAIT backstop rather than the
    // earlier backend-count check.
    let observer = raw_client(&url).await;
    let baseline = total_backends(&observer).await;
    let mut client = deadpool_client(&url).await;
    let refused = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "should be refused by the table lock backstop",
        baseline + 1,
    )
    .await;
    assert!(
        matches!(refused, Err(DomainError::Contention(_))),
        "expected Contention, got {refused:?}"
    );

    lock_tx.rollback().await.expect("release the held lock");

    let retry_baseline = total_backends(&observer).await;
    let mut retry_client = deadpool_client(&url).await;
    let applied = event_plane::set_event_plane(
        &mut retry_client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "retry once the lock is released",
        retry_baseline + 1,
    )
    .await
    .expect("the retry must succeed once the lock is released");
    assert!(matches!(applied, SetEventPlaneOutcome::Applied { .. }));
}

#[tokio::test]
#[ignore = "requires LORE_TEST_PG_URL"]
async fn read_boot_facts_reports_the_marker_and_whether_the_cell_holds_any_outbox_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();

    let facts = store
        .event_plane_boot_facts(&cell_id)
        .await
        .expect("boot facts for a never-switched cell");
    assert_eq!(facts.marker.plane, EventPlane::Durable);
    assert_eq!(facts.marker.transition_seq, 0);
    assert!(!facts.has_outbox_rows);

    let mut raw = raw_client(&url).await;
    append_pending(&mut raw, &cell_id, &repository_id).await;
    let facts_with_row = store
        .event_plane_boot_facts(&cell_id)
        .await
        .expect("boot facts once the cell holds a row");
    assert!(facts_with_row.has_outbox_rows);

    let baseline = total_backends(&raw).await;
    let mut client = deadpool_client(&url).await;
    let result = event_plane::set_event_plane(
        &mut client,
        &cell_id,
        EventPlane::LiveOnly,
        "operator-a",
        "n/a: this call must refuse",
        baseline + 1,
    )
    .await;
    assert!(
        matches!(result, Err(DomainError::NotReady(_))),
        "expected NotReady from the still-pending row, got {result:?}"
    );
}
