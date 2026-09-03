// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step B: failure classification -> disposition, batch isolation,
//! stale-claim fencing, and bounded drain over
//! `lore-server/src/event_relay/worker.rs`'s `process_claimed`/`run`.
//!
//! `worker.rs`, `envelope_map.rs`, and `config.rs` each already carry
//! thorough `#[cfg(test)]` coverage of the pure classification/mapping/
//! backoff logic (every `MapFailure` variant's terminal class,
//! `acceptance_record`'s range checks, `cas_label`'s exhaustive mapping,
//! `RelayBackoff::next_delay`'s jitter/cap/floor) -- this file does not
//! duplicate any of that. What only a live-Postgres integration test can
//! add: the classification wired end to end through a real claimed row and
//! a real `FakeGateway`, batch isolation across several rows in one claim,
//! stale-claim fencing across two real claimants, and a bounded drain of a
//! real running loop.
//!
//! Real Postgres only, `#[ignore]`. See `event_relay_publish.rs`'s module
//! docs for the shared database/schema-namespace convention.

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "common/relay_harness.rs"]
mod relay_harness;

use std::time::Duration;

use case_namespace::CaseNamespace;
use lore_postgres::domain::outbox::relay::MAX_CLAIM_BATCH;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_server::event_relay::RowOutcome;
use lore_server::plugins::remote_notification::fake_gateway::FakeGateway;
use lore_server::plugins::remote_notification::fake_gateway::ScriptedResponse;
use lore_server::plugins::remote_notification::wire;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

// ---------------------------------------------------------------------------
// Classification -> disposition
// ---------------------------------------------------------------------------

/// A gateway scripted `Transient` (`Status::unavailable`) releases the row
/// for retry: `state` stays `pending`, `attempt_count` increments, and
/// `available_at` moves into the future.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_transient_failure_releases_the_row_for_retry_with_available_at_in_the_future() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "transient").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    let event_id = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;

    let pool = relay_harness::test_pool(&url).await;
    let gateway = FakeGateway::always(ScriptedResponse::unavailable());
    let worker = relay_harness::build_worker(pool.clone(), gateway, "worker-a");

    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch");
    assert_eq!(claimed.len(), 1);
    let claimed = claimed.remove(0);
    let attempt_before = claimed.attempt_count;
    drop(client);

    // Captured BEFORE the release, and compared against the stored
    // available_at rather than against `clock_timestamp()` read back later:
    // fast_test_config's backoff base is only 10ms, so comparing against
    // "now" at READ time races ordinary Postgres round-trip latency and can
    // read `false` even though the release genuinely pushed available_at
    // forward. Comparing against a "before" anchor is race-free regardless
    // of how small the backoff is.
    let before_release: std::time::SystemTime = relay_harness::raw_client(&url)
        .await
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .expect("read the database's own clock")
        .get(0);

    let outcome = worker.process_claimed(claimed).await;
    assert_eq!(
        outcome,
        RowOutcome::Requeued,
        "a Transient publish failure must Requeue the row"
    );

    let raw = relay_harness::raw_client(&url).await;
    let row = raw
        .query_one(
            "SELECT state, attempt_count, available_at FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("row must still exist");
    assert_eq!(row.get::<_, String>("state"), "pending");
    assert_eq!(row.get::<_, i32>("attempt_count"), attempt_before + 1);
    let available_at: std::time::SystemTime = row.get("available_at");
    assert!(
        available_at > before_release,
        "available_at ({available_at:?}) must be pushed strictly past the pre-release anchor \
         ({before_release:?}) -- the backoff floor guarantees at least 1ms of delay"
    );
    namespace.release().await;
}

/// `NotAccepted` (an unversioned ack) also Requeues the row with its
/// ORIGINAL stable keys -- distinct from Terminal, since the publish may
/// still have landed.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_not_accepted_result_retains_the_row_pending_with_its_original_stable_keys() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "not-accepted").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    let event_id = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;
    let raw = relay_harness::raw_client(&url).await;
    let before: Vec<u8> = raw
        .query_one(
            "SELECT idempotency_key FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("row exists")
        .get("idempotency_key");

    let pool = relay_harness::test_pool(&url).await;
    let gateway = FakeGateway::always(ScriptedResponse::unversioned_ack());
    let worker = relay_harness::build_worker(pool.clone(), gateway, "worker-a");

    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch");
    assert_eq!(claimed.len(), 1);
    drop(client);
    let outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(
        outcome,
        RowOutcome::Requeued,
        "NotAccepted must Requeue (not dead-letter) the row"
    );

    let row = raw
        .query_one(
            "SELECT state, idempotency_key FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("row must still exist under its original keys");
    assert_eq!(row.get::<_, String>("state"), "pending");
    assert_eq!(row.get::<_, Vec<u8>>("idempotency_key"), before);
    namespace.release().await;
}

/// A gateway scripted `Terminal` (a wire `TERMINAL`/`SCOPE_MISMATCH` result)
/// dead-letters the row with the `scope_mismatch` terminal class, and the
/// row leaves `lore_outbox_events` (Step A's `dead_letter()`
/// deletes-and-copies).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_terminal_failure_dead_letters_the_row_and_it_leaves_the_live_table() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "terminal").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    let event_id = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;

    let pool = relay_harness::test_pool(&url).await;
    let terminal_result = wire::PublishResultV1 {
        transport_version: wire::TRANSPORT_VERSION,
        outcome: wire::PublishOutcomeV1::Terminal as i32,
        failure_class: wire::PublishFailureClassV1::ScopeMismatch as i32,
        ..Default::default()
    };
    let gateway = FakeGateway::always(ScriptedResponse::Result(Box::new(terminal_result)));
    let worker = relay_harness::build_worker(pool.clone(), gateway, "worker-a");

    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch");
    assert_eq!(claimed.len(), 1);
    drop(client);
    let outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(outcome, RowOutcome::DeadLettered);

    let raw = relay_harness::raw_client(&url).await;
    let live = raw
        .query_opt(
            "SELECT 1 FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("query live table");
    assert!(
        live.is_none(),
        "a dead-lettered row must leave lore_outbox_events"
    );

    let dead = raw
        .query_one(
            "SELECT terminal_class, disposition FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter row must exist");
    assert_eq!(dead.get::<_, String>("disposition"), "parked");
    // "scope_mismatch" is TerminalClass::ScopeMismatch::as_metric_label()'s
    // own value, not a guess -- ScopeMismatch is one of the three classes
    // worker.rs's terminal_is_final treats as final on sight (see that
    // function's own doc comment), unlike InvalidRequest below.
    assert_eq!(dead.get::<_, String>("terminal_class"), "scope_mismatch");
    namespace.release().await;
}

/// CR-032's wording is a **repeated** event-specific 4xx, not a bare one,
/// and the fix round's second pass pinned "repeated" as strictly
/// CONSECUTIVE (`ClaimedEvent::last_error_class`), not a 20-attempt/1-hour
/// window -- a row that sat through a broker outage would otherwise arrive
/// at its first genuine rejection already looking like a repeat offender.
/// `TerminalClass::InvalidRequest` (a gateway `INVALID_ARGUMENT`) must
/// Requeue on the FIRST occurrence (no prior `last_error_class` to match)
/// and dead-letter on the SECOND CONSECUTIVE occurrence of the identical
/// class. The sibling `a_terminal_failure_dead_letters_the_row_and_it_leaves_the_live_table`
/// case above uses `ScopeMismatch`, which is unaffected (final on sight),
/// so that test's assertion is still exercising what it always exercised --
/// this one exercises the newly-gated class specifically, both halves of
/// the rule.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn invalid_request_requeues_once_then_dead_letters_on_the_immediate_repeat() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "invreq-repeat").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    let event_id = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;

    let pool = relay_harness::test_pool(&url).await;
    // classify_status maps Code::InvalidArgument to
    // PublishFailure::Terminal(TerminalClass::InvalidRequest), on every call.
    let gateway = FakeGateway::always(ScriptedResponse::Status(
        tonic::Code::InvalidArgument,
        "bad scope".to_string(),
    ));
    let worker = relay_harness::build_worker(pool.clone(), gateway, "worker-a");
    let raw = relay_harness::raw_client(&url).await;

    // First attempt: no last_error_class yet, so this must Requeue and
    // stamp last_error_class = "invalid_request" (TerminalClass::InvalidRequest's
    // own metric label) for the next claim to compare against.
    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch (first attempt)");
    assert_eq!(claimed.len(), 1);
    assert_eq!(
        claimed[0].last_error_class, None,
        "a freshly appended row must have no last_error_class yet"
    );
    drop(client);
    let first_outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(
        first_outcome,
        RowOutcome::Requeued,
        "the FIRST InvalidRequest rejection must Requeue, not dead-letter"
    );
    let row = raw
        .query_one(
            "SELECT state, last_error_class FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("the row must still be live after the first rejection");
    assert_eq!(row.get::<_, String>("state"), "pending");
    let stamped_class: String = row.get("last_error_class");
    assert!(
        !stamped_class.is_empty(),
        "last_error_class must be stamped so the next attempt can compare against it"
    );

    // Second attempt, same class: must now dead-letter. available_at was
    // pushed into the future by the backoff, so wait it out (fast_test_config's
    // base is 10ms) before reclaiming.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch (second attempt)");
    assert_eq!(
        claimed.len(),
        1,
        "the row must be reclaimable after its short backoff"
    );
    assert_eq!(
        claimed[0].last_error_class.as_deref(),
        Some(stamped_class.as_str()),
        "the second claim must observe the class stamped by the first attempt"
    );
    drop(client);
    let second_outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(
        second_outcome,
        RowOutcome::DeadLettered,
        "the SECOND CONSECUTIVE InvalidRequest rejection must dead-letter"
    );
    let live = raw
        .query_opt(
            "SELECT 1 FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("query live table");
    assert!(
        live.is_none(),
        "a dead-lettered row must leave lore_outbox_events"
    );
    let dead = raw
        .query_one(
            "SELECT terminal_class FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter row must exist");
    assert_eq!(dead.get::<_, String>("terminal_class"), stamped_class);
    namespace.release().await;
}

/// A gateway acceptance whose `broker_sequence` does not fit `i64` (the
/// store column's type) follows the SAME consecutive-repetition rule as
/// `InvalidRequest` above (the fix round's second correction, replacing an
/// unbounded republish loop with a bounded one): the first occurrence
/// Requeues under the `acceptance_evidence_out_of_range` class, and the
/// second consecutive occurrence dead-letters.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn an_out_of_range_broker_sequence_requeues_once_then_dead_letters_on_the_immediate_repeat() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "accept-oor").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    let event_id = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;

    let pool = relay_harness::test_pool(&url).await;
    // A complete, versioned acceptance (passes client.rs's classify_result
    // gate: non-empty stream_identity, non-zero epoch/sequence, matching
    // contract version) whose broker_sequence is u64::MAX -- valid on the
    // wire, unrepresentable in the store's bigint column. Scripted on every
    // call, matching the real gateway continuing to answer the same way.
    let out_of_range_accept = || wire::PublishResultV1 {
        transport_version: wire::TRANSPORT_VERSION,
        outcome: wire::PublishOutcomeV1::Accepted as i32,
        stream_identity: "DURABLE-oor-test".to_string(),
        stream_epoch: 1,
        broker_sequence: u64::MAX,
        publisher_contract_version: wire::TRANSPORT_VERSION,
        ..Default::default()
    };
    let gateway = FakeGateway::always(ScriptedResponse::Result(Box::new(out_of_range_accept())));
    let worker = relay_harness::build_worker(pool.clone(), gateway, "worker-a");
    let raw = relay_harness::raw_client(&url).await;

    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch (first attempt)");
    assert_eq!(claimed.len(), 1);
    drop(client);
    let first_outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(
        first_outcome,
        RowOutcome::Requeued,
        "the FIRST out-of-range acceptance must Requeue, not dead-letter or loop"
    );
    let row = raw
        .query_one(
            "SELECT state, last_error_class FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("the row must still be live after the first out-of-range acceptance");
    assert_eq!(row.get::<_, String>("state"), "pending");
    assert_eq!(
        row.get::<_, String>("last_error_class"),
        "acceptance_evidence_out_of_range"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch (second attempt)");
    assert_eq!(
        claimed.len(),
        1,
        "the row must be reclaimable after its short backoff"
    );
    assert_eq!(
        claimed[0].last_error_class.as_deref(),
        Some("acceptance_evidence_out_of_range")
    );
    drop(client);
    let outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(
        outcome,
        RowOutcome::DeadLettered,
        "the SECOND CONSECUTIVE out-of-range acceptance must dead-letter the row rather than loop"
    );

    let dead = raw
        .query_one(
            "SELECT terminal_class, disposition FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter row must exist");
    assert_eq!(dead.get::<_, String>("disposition"), "parked");
    assert_eq!(
        dead.get::<_, String>("terminal_class"),
        "acceptance_evidence_out_of_range"
    );
    namespace.release().await;
}

/// A row whose `map_event` fails (an undecodable `aggregate_version`,
/// written below `append()`'s own validation to simulate schema drift) is
/// dead-lettered WITHOUT ever calling the gateway.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_row_that_fails_envelope_mapping_is_dead_lettered_without_calling_the_gateway() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "bad-map").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    let event_id = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;
    // Poison the row below append()'s own validation: the column CHECK
    // admits up to 256 bytes (wider than Step A's Rust-side 8..=128 bound),
    // so 200 bytes clears the CHECK but fails AggregateVersion::decode /
    // map_event with MapFailure::AggregateVersionUndecodable.
    let raw = relay_harness::raw_client(&url).await;
    raw.execute(
        "UPDATE lore_outbox_events SET aggregate_version = $2 WHERE event_id = $1",
        &[&event_id, &vec![0u8; 200]],
    )
    .await
    .expect("poison aggregate_version below the Rust-side bound");

    let pool = relay_harness::test_pool(&url).await;
    let gateway = FakeGateway::accepting();
    let worker = relay_harness::build_worker(pool.clone(), gateway.clone(), "worker-a");

    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch");
    assert_eq!(claimed.len(), 1);
    drop(client);
    let outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(outcome, RowOutcome::DeadLettered);
    assert_eq!(
        gateway.request_count(),
        0,
        "the gateway must never be called for a row that fails envelope mapping"
    );
    let dead_letter_exists = raw
        .query_opt(
            "SELECT 1 FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("query dead letters");
    assert!(dead_letter_exists.is_some());
    namespace.release().await;
}

/// One failing row in a claimed batch never delays the later rows in the
/// SAME batch.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_failing_row_never_delays_later_rows_in_the_same_batch() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "batch-isolation").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();

    let failing = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;
    let mut others = Vec::new();
    for i in 2..=5u64 {
        others.push(
            relay_harness::append_pending(
                &url,
                &repository_id,
                "branch.pushed",
                "branch",
                &relay_harness::rand_repository_id(),
                i,
            )
            .await,
        );
    }

    let pool = relay_harness::test_pool(&url).await;
    let terminal_result = wire::PublishResultV1 {
        transport_version: wire::TRANSPORT_VERSION,
        outcome: wire::PublishOutcomeV1::Terminal as i32,
        failure_class: wire::PublishFailureClassV1::ScopeMismatch as i32,
        ..Default::default()
    };
    let gateway = FakeGateway::scripted_with_fallback(
        [ScriptedResponse::Result(Box::new(terminal_result))],
        ScriptedResponse::accept(),
    );
    let worker = relay_harness::build_worker(pool.clone(), gateway, "worker-a");

    let mut client = pool.get().await.expect("checkout pool client");
    let claimed = claim_batch(
        &mut client,
        "worker-a",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("claim_batch");
    assert_eq!(
        claimed.len(),
        5,
        "expected all 5 seeded rows claimed together"
    );
    drop(client);

    for row in claimed {
        worker.process_claimed(row).await;
    }

    let raw = relay_harness::raw_client(&url).await;
    let failing_live = raw
        .query_opt(
            "SELECT 1 FROM lore_outbox_events WHERE event_id = $1",
            &[&failing],
        )
        .await
        .expect("query");
    assert!(
        failing_live.is_none(),
        "the failing row must be dead-lettered out of the live table"
    );

    for id in &others {
        let state: String = raw
            .query_one(
                "SELECT state FROM lore_outbox_events WHERE event_id = $1",
                &[id],
            )
            .await
            .unwrap_or_else(|e| panic!("row {id} must still exist: {e}"))
            .get("state");
        assert_eq!(state, "broker_accepted", "row {id} must have been accepted");
    }
    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Stale-worker fencing
// ---------------------------------------------------------------------------

/// A worker holding a stale claim generation -- superseded by a second
/// claimer after the first's 300ms test lease expired -- is fenced by the
/// store's own `CasOutcome::StaleClaim` inside `ensure_lease`'s renewal
/// attempt, drops the row without publishing, and the row's actual state
/// afterward is the SECOND (newer) claimant's, read directly rather than
/// merely asserted "unchanged".
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_worker_holding_a_stale_claim_generation_is_fenced_before_ever_publishing() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "stale-fencing").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    let event_id = relay_harness::append_pending(
        &url,
        &repository_id,
        "branch.pushed",
        "branch",
        &relay_harness::rand_repository_id(),
        1,
    )
    .await;

    let pool = relay_harness::test_pool(&url).await;
    let lease = Duration::from_millis(300);

    let stale_claim = {
        let mut client = pool.get().await.expect("checkout pool client");
        let mut claimed = claim_batch(&mut client, "worker-a", 1, lease)
            .await
            .expect("worker-a's initial claim");
        assert_eq!(claimed.len(), 1);
        claimed.remove(0)
    };

    // Let worker-a's lease expire, then a second claimant reclaims it.
    tokio::time::sleep(lease + Duration::from_millis(150)).await;
    let newer_claim = {
        let mut client = pool.get().await.expect("checkout pool client");
        let mut claimed = claim_batch(&mut client, "worker-b", 1, lease)
            .await
            .expect("worker-b's reclaim after expiry");
        assert_eq!(
            claimed.len(),
            1,
            "worker-b must be able to reclaim the expired lease"
        );
        claimed.remove(0)
    };
    assert!(
        newer_claim.claim_generation > stale_claim.claim_generation,
        "the reclaim must stamp a strictly newer generation"
    );

    // Drive worker-a's OWN process_claimed on the now-stale ClaimedEvent it
    // captured before the reclaim -- this models it finally returning from
    // whatever kept it from renewing/publishing in time.
    let gateway = FakeGateway::accepting();
    let worker_a = relay_harness::build_worker(pool.clone(), gateway.clone(), "worker-a");
    let outcome = worker_a.process_claimed(stale_claim).await;
    assert_eq!(
        outcome,
        RowOutcome::Fenced,
        "a stale claim generation must be fenced, not published or requeued"
    );
    assert_eq!(
        gateway.request_count(),
        0,
        "a fenced row must never reach the gateway -- ensure_lease's renewal check runs before publish"
    );

    let raw = relay_harness::raw_client(&url).await;
    let row = raw
        .query_one(
            "SELECT state, claim_owner, claim_generation FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("row must still exist under the newer claim");
    assert_eq!(row.get::<_, String>("state"), "pending");
    assert_eq!(
        row.get::<_, Option<String>>("claim_owner"),
        Some("worker-b".to_string())
    );
    assert_eq!(
        row.get::<_, i64>("claim_generation"),
        newer_claim.claim_generation
    );
    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

/// Beginning drain (flipping the `watch::Sender` to `true`) stops the loop
/// BETWEEN rows of the batch currently in flight, not after the whole batch
/// finishes -- corrected by a reviewer fix round from this suite's earlier
/// (wrong) name and assertions, which assumed the batch ran to completion.
/// `worker.rs`'s own module docs now state why: `batch_size` publishes at
/// the publish deadline is over sixteen minutes at the shipped defaults, and
/// a cell with `graceful_drain` on and no drain timeout has no backstop
/// that would cut it short. The row already in flight when drain is
/// signalled completes (the shutdown check runs between rows, not
/// preemptively), and every row behind it in the batch is abandoned with
/// its claim and lease intact -- a reclaimable uncompleted claim, which is
/// exactly what CR-032's drain requirement allows.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn drain_completes_the_in_flight_row_abandons_the_rest_of_the_batch_to_their_leases_and_the_worker_terminates()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "drain").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    // `claim_batch` orders by `(available_at, event_id)`; three rows
    // appended in a tight loop can land with near-identical `available_at`
    // values, so the tiebreak is effectively the UUID and WHICH of these
    // three is claimed (and therefore processed) first is not something
    // this test can predict from insertion order alone -- confirmed:
    // hardcoding "ordinal 1 claims first" here failed intermittently
    // because it sometimes wasn't. The assertions below determine which one
    // was in flight empirically instead of assuming it.
    let seeded = relay_harness::append_n_pending(&url, &repository_id, 3).await;

    let pool = relay_harness::test_pool(&url).await;
    // The first Publish call hangs long enough to signal drain while it is
    // still outstanding; every later call (there should be none, in the
    // abandoned rows' case) would accept.
    let gateway = FakeGateway::scripted_with_fallback(
        [ScriptedResponse::Hang(Duration::from_millis(400))],
        ScriptedResponse::accept(),
    );
    // relay_harness::fast_test_config's publish_deadline (100ms) is shorter
    // than this Hang: PrivateGatewayClient enforces the deadline with its
    // own tokio::time::timeout around the transport call, so a Hang longer
    // than the deadline is classified Transient::Timeout, never reaches
    // Ok(acceptance), and the in-flight row would be Requeued instead of
    // Accepted (reproduced: every row ended up "pending", none
    // "broker_accepted"). Build a config with a longer publish_deadline for
    // this test specifically, keeping the short claim_lease so the
    // abandoned-rows reclaim step below stays fast; a renewal mid-Hang is
    // harmless (ensure_lease just extends the lease and returns true).
    let config = lore_server::event_relay::EventRelayConfig {
        publish_deadline: Duration::from_secs(2),
        ..relay_harness::fast_test_config("worker-a")
    };
    let publisher = relay_harness::publisher_over(gateway.clone());
    let readiness = std::sync::Arc::new(lore_server::event_relay::EventRelayReadiness::new(
        Duration::from_secs(30),
        Duration::from_secs(5),
        config.publish_deadline,
    ));
    let worker = lore_server::event_relay::EventRelayWorker::new(
        pool.clone(),
        publisher,
        config,
        readiness,
        relay_harness::envelope_source(),
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = lore_base::lore_spawn!(async move { worker.run(shutdown_rx).await });

    // Poll for the gateway's first request rather than sleeping a fixed
    // guess: `FakeGateway::Hang` does not answer until its duration
    // elapses, so `request_count() >= 1` is proof the worker is genuinely
    // inside the in-flight publish call right now, not "probably has been
    // long enough" -- a blind sleep here previously raced the worker's own
    // pre-claim readiness probe and initial claim round trip and could fire
    // before the row was even claimed, at which point the loop's top-of-loop
    // shutdown check would break before ever claiming anything (reproduced:
    // the in-flight row stayed "pending" rather than reaching
    // "broker_accepted").
    for _ in 0..100 {
        if gateway.request_count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        gateway.request_count(),
        1,
        "the worker must have entered the in-flight row's publish call before drain is signalled"
    );
    shutdown_tx.send(true).expect("signal drain");

    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("worker.run() must resolve within the bounded timeout after drain")
        .expect("the spawned task must not panic")
        .expect("worker.run() must return Ok on a clean drain");

    assert_eq!(
        gateway.request_count(),
        1,
        "only the row that was in flight when drain was signalled must have reached the \
         gateway -- the rest of the batch must be abandoned before ever publishing"
    );

    let raw = relay_harness::raw_client(&url).await;
    let mut accepted = Vec::new();
    let mut abandoned = Vec::new();
    for id in &seeded {
        let state: String = raw
            .query_one(
                "SELECT state FROM lore_outbox_events WHERE event_id = $1",
                &[id],
            )
            .await
            .unwrap_or_else(|e| panic!("row {id} must still exist: {e}"))
            .get("state");
        match state.as_str() {
            "broker_accepted" => accepted.push(*id),
            "pending" => abandoned.push(*id),
            other => panic!("row {id} has unexpected state {other:?}"),
        }
    }
    assert_eq!(
        accepted.len(),
        1,
        "exactly one row -- whichever was in flight -- must have completed; got {accepted:?}"
    );
    assert_eq!(
        abandoned.len(),
        2,
        "the other two rows must be abandoned untouched (pending), not published; got {abandoned:?}"
    );

    // The abandoned rows' claims are reclaimable once their lease expires --
    // proven by actually reclaiming and completing them with a fresh
    // worker/claim, not merely by inspecting the row.
    tokio::time::sleep(
        relay_harness::fast_test_config("worker-a").claim_lease + Duration::from_millis(150),
    )
    .await;
    let gateway_b = FakeGateway::accepting();
    let worker_b = relay_harness::build_worker(pool.clone(), gateway_b.clone(), "worker-b");
    let mut client = pool.get().await.expect("checkout pool client");
    let reclaimed = claim_batch(
        &mut client,
        "worker-b",
        MAX_CLAIM_BATCH,
        Duration::from_secs(30),
    )
    .await
    .expect("reclaim the abandoned rows after their lease expires");
    assert_eq!(
        reclaimed.len(),
        abandoned.len(),
        "both abandoned rows must be reclaimable once their lease expires"
    );
    drop(client);
    for row in reclaimed {
        let outcome = worker_b.process_claimed(row).await;
        assert_eq!(outcome, RowOutcome::Accepted);
    }
    for id in &abandoned {
        let state: String = raw
            .query_one(
                "SELECT state FROM lore_outbox_events WHERE event_id = $1",
                &[id],
            )
            .await
            .expect("row exists")
            .get("state");
        assert_eq!(
            state, "broker_accepted",
            "row {id} must complete once reclaimed and processed"
        );
    }
    namespace.release().await;
}
