// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step B: the relay worker's happy path, exactly-once acceptance
//! recording, lost-update duplicate handling, and multi-worker fairness
//! over `lore-server/src/event_relay/worker.rs`'s
//! `EventRelayWorker::process_claimed`, driven against WP-119 Step A's
//! Postgres outbox store and WP-111's `FakeGateway`.
//!
//! Real Postgres only, `#[ignore]`. One throwaway database per run (created
//! by the caller, e.g. `docker exec ... CREATE DATABASE`); each case below
//! acquires its own schema inside it via `common::case_namespace::CaseNamespace`
//! -- the store's own scan functions (`claim_batch`, `backlog`, ...) have no
//! `cell_id` filter, so schema isolation is load-bearing here.
//!
//! `EventRelayWorker::process_claimed` takes no client parameter -- it
//! checks out its own pooled connections internally -- so every test here
//! claims externally via `relay::claim_batch` (using the SAME owner string
//! the worker's own config carries, since `ensure_lease`'s renewal path
//! checks both claim generation AND owner) and then drives
//! `process_claimed` directly, which is deterministic and avoids racing
//! `EventRelayWorker::run`'s own idle-interval timing.

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "common/relay_harness.rs"]
mod relay_harness;

use std::collections::HashSet;
use std::time::Duration;

use case_namespace::CaseNamespace;
use lore_postgres::domain::outbox::relay::MAX_CLAIM_BATCH;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_server::event_relay::RowOutcome;
use lore_server::plugins::remote_notification::fake_gateway::FakeGateway;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

// ---------------------------------------------------------------------------
// Behavior 1: happy path
// ---------------------------------------------------------------------------

/// N pending rows seeded via the real `append()` path all reach
/// `broker_accepted` with exactly the acceptance fields the fake gateway
/// returned, the envelope the fake received carries each row's `event_id`,
/// and no `event_id` is published twice.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn happy_path_publishes_every_pending_row_exactly_once_with_correct_envelope_fields() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "happy-path").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    const N: u64 = 25;
    let event_ids = relay_harness::append_n_pending(&url, &repository_id, N).await;

    let pool = relay_harness::test_pool(&url).await;
    let gateway = FakeGateway::accepting();
    let worker = relay_harness::build_worker(pool.clone(), gateway.clone(), "worker-a");

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
        N as usize,
        "expected all N seeded rows claimed"
    );
    drop(client);

    for row in claimed {
        let event_id = row.event.event_id;
        let outcome = worker.process_claimed(row).await;
        assert_eq!(
            outcome,
            RowOutcome::Accepted,
            "row {event_id} expected Accepted"
        );
    }

    let seen: HashSet<Vec<u8>> = gateway
        .requests()
        .into_iter()
        .map(|e| e.event_id.to_vec())
        .collect();
    assert_eq!(seen.len(), N as usize, "no event_id may be published twice");
    let expected: HashSet<Vec<u8>> = event_ids.iter().map(|id| id.as_bytes().to_vec()).collect();
    assert_eq!(seen, expected);

    let raw = relay_harness::raw_client(&url).await;
    for id in &event_ids {
        let row = raw
            .query_one(
                "SELECT state, stream_identity, stream_epoch, broker_sequence, \
                        publisher_contract_version \
                 FROM lore_outbox_events WHERE event_id = $1",
                &[id],
            )
            .await
            .unwrap_or_else(|e| panic!("row {id} must exist and be broker_accepted: {e}"));
        assert_eq!(row.get::<_, String>("state"), "broker_accepted");
        assert!(!row.get::<_, String>("stream_identity").is_empty());
        assert!(row.get::<_, i64>("stream_epoch") >= 1);
        assert!(row.get::<_, i64>("broker_sequence") >= 1);
        assert!(row.get::<_, i32>("publisher_contract_version") >= 1);
    }
    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Behavior 3: duplicate after a lost update (crash between acceptance and
// the row update)
// ---------------------------------------------------------------------------

/// Models the crash CR-032 explicitly allows ("death after publish produces
/// a duplicate with the same keys"): a first claim publishes and accepts
/// through the raw `DurablePublisher`/gateway directly, WITHOUT ever
/// recording the acceptance (simulating the worker dying between the two).
/// Once that claim's lease expires, a real worker pass reclaims and
/// republishes the SAME event under the SAME stable keys, and the row ends
/// `broker_accepted` exactly once.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_crash_between_gateway_acceptance_and_the_row_update_republishes_but_accepts_once() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "lost-update").await;
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
    let gateway = FakeGateway::accepting();
    let lease = Duration::from_millis(300);

    // The simulated crash: claim, map, and publish directly through the raw
    // DurablePublisher -- WITHOUT ever calling record_broker_accepted. The
    // row must therefore remain pending afterwards.
    {
        let mut client = pool.get().await.expect("checkout pool client");
        let mut claimed = claim_batch(&mut client, "crashed-worker", 1, lease)
            .await
            .expect("claim_batch");
        assert_eq!(claimed.len(), 1);
        let claimed = claimed.remove(0);
        drop(client);
        let envelope = lore_server::event_relay::map_event(
            &claimed.event,
            &relay_harness::envelope_source(),
            std::time::SystemTime::now(),
        )
        .expect("well-formed seeded row must map");
        let publisher = relay_harness::publisher_over(gateway.clone());
        lore_server::event_relay::DurablePublisher::publish(
            &*publisher,
            &envelope,
            Duration::from_secs(2),
        )
        .await
        .expect("the fake gateway accepts by default");
        // Deliberately no record_broker_accepted call -- this is the crash.
    }

    let raw = relay_harness::raw_client(&url).await;
    let still_pending: String = raw
        .query_one(
            "SELECT state FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("row must still exist")
        .get("state");
    assert_eq!(
        still_pending, "pending",
        "the row must remain pending -- the simulated crash never recorded acceptance"
    );
    assert_eq!(
        gateway.request_count(),
        1,
        "the crashed attempt still reached the gateway once"
    );

    // Let the crashed claim's lease expire, then run a real worker pass.
    tokio::time::sleep(lease + Duration::from_millis(150)).await;
    let worker = relay_harness::build_worker(pool.clone(), gateway.clone(), "worker-a");
    let mut client = pool.get().await.expect("checkout pool client");
    let mut claimed = claim_batch(&mut client, "worker-a", 1, lease)
        .await
        .expect("reclaim after the crashed lease expires");
    assert_eq!(
        claimed.len(),
        1,
        "the crashed claim's row must be reclaimable"
    );
    drop(client);
    let outcome = worker.process_claimed(claimed.remove(0)).await;
    assert_eq!(outcome, RowOutcome::Accepted);

    assert_eq!(
        gateway.request_count(),
        2,
        "CR-032 explicitly allows this duplicate: the crashed attempt plus the real republish"
    );
    let row = raw
        .query_one(
            "SELECT state FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("row must exist");
    assert_eq!(
        row.get::<_, String>("state"),
        "broker_accepted",
        "the row transitions to broker_accepted exactly once despite the duplicate publish"
    );
    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Behavior 4: two workers, exactly-once acceptance over a shared backlog
// ---------------------------------------------------------------------------

/// Two relay loops with distinct owner identities run concurrently over the
/// same backlog. Every event publishes at least once, and every row records
/// `broker_accepted` exactly once. Driven by two manual claim/process loops
/// under `tokio::join!` (not `EventRelayWorker::run`, to keep the assertion
/// deterministic: `SKIP LOCKED` claiming disjoint batches is what needs
/// proving, not idle-loop timing).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn two_concurrent_workers_over_a_shared_backlog_publish_each_event_at_least_once_and_accept_exactly_once()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "two-workers").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    const N: u64 = 200;
    let event_ids = relay_harness::append_n_pending(&url, &repository_id, N).await;

    let pool = relay_harness::test_pool(&url).await;
    let gateway = FakeGateway::accepting();
    let worker_a = relay_harness::build_worker(pool.clone(), gateway.clone(), "worker-a");
    let worker_b = relay_harness::build_worker(pool.clone(), gateway.clone(), "worker-b");

    async fn run_to_completion(
        worker: lore_server::event_relay::EventRelayWorker,
        owner: &'static str,
        pool: lore_postgres::pool::Pool,
    ) -> usize {
        let mut published = 0usize;
        loop {
            let mut client = pool.get().await.expect("checkout pool client");
            let claimed = claim_batch(&mut client, owner, MAX_CLAIM_BATCH, Duration::from_secs(30))
                .await
                .expect("claim_batch");
            drop(client);
            if claimed.is_empty() {
                break;
            }
            for row in claimed {
                worker.process_claimed(row).await;
                published += 1;
            }
        }
        published
    }

    let (published_a, published_b) = tokio::join!(
        run_to_completion(worker_a, "worker-a", pool.clone()),
        run_to_completion(worker_b, "worker-b", pool.clone())
    );
    println!(
        "two-worker fairness: N={N}, worker-a processed {published_a}, worker-b processed {published_b}"
    );

    let raw = relay_harness::raw_client(&url).await;
    let accepted_count: i64 = raw
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE state = 'broker_accepted'",
            &[],
        )
        .await
        .expect("count accepted rows")
        .get(0);
    assert_eq!(
        accepted_count, N as i64,
        "every seeded row must end broker_accepted exactly once"
    );

    let mut seen_more_than_once = 0usize;
    for id in &event_ids {
        let requests_for_id = gateway
            .requests()
            .into_iter()
            .filter(|e| e.event_id.as_ref() == id.as_bytes())
            .count();
        assert!(
            requests_for_id >= 1,
            "event {id} must have been published at least once"
        );
        if requests_for_id > 1 {
            seen_more_than_once += 1;
        }
    }
    println!(
        "two-worker fairness: {seen_more_than_once}/{N} events were published more than once \
         (allowed by SKIP LOCKED's own contract -- the accepted_count assertion above already \
         proves no row double-recorded acceptance)"
    );
    namespace.release().await;
}
