// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Phase 8: the relay's drain-rate **measurement instrument**.
//!
//! This is not a behavioral gate and deliberately asserts almost nothing. It
//! exists to produce the number in `event_relay::admission::ADMISSION_RETRY_DELAY`'s
//! doc comment: CR-032 requires that delay to be derived from a measured drain
//! rate rather than guessed, and a measurement nobody can re-run is not
//! evidence of anything a year from now.
//!
//! What it measures: the relay's claim/publish/settle loop against a real local
//! Postgres with a seeded backlog, publishing through WP-111's in-process
//! `FakeGateway`.
//!
//! **What that number is and is not.** The fake gateway accepts immediately
//! over an in-process channel, so this isolates the Postgres and worker cost
//! and excludes the network publish entirely. It is therefore an **upper bound
//! on the drain rate**, not a production estimate — a real gateway publish adds
//! its own latency per row, bounded by `publish_deadline`. That direction is
//! the right one for deriving a retry delay: a delay justified against an
//! optimistic drain rate is conservative when the real rate is lower, because
//! it means the relay has had *at least* the assumed amount of time.
//!
//! Run it (PowerShell, from the fork root), against the local dataplane
//! Postgres:
//!
//! ```text
//! docker exec lorehub-dataplane-test-postgres-1 psql -U lorehub -d postgres `
//!     -c "DROP DATABASE IF EXISTS wp119_drain; CREATE DATABASE wp119_drain;"
//! $env:LORE_TEST_PG_URL = "postgresql://lorehub:lorehub@127.0.0.1:11832/wp119_drain"
//! cargo test -p lore-server --test outbox_drain_rate -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The numbers it printed on the run that set the shipped constant are recorded
//! in `ADMISSION_RETRY_DELAY`'s own doc comment, with the rig they came from.

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "common/relay_harness.rs"]
mod relay_harness;

use std::time::Duration;
use std::time::Instant;

use case_namespace::CaseNamespace;
use lore_postgres::domain::outbox::relay::MAX_CLAIM_BATCH;
use lore_postgres::domain::outbox::relay::backlog;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_server::event_relay::RowOutcome;
use lore_server::plugins::remote_notification::fake_gateway::FakeGateway;

/// CR-032's brief for this measurement: at least ten thousand rows.
const SEEDED_ROWS: i64 = 10_000;

/// Payload width per seeded row.
///
/// 512 bytes rather than the 64 KiB cap: CR-032's payloads are bounded identity
/// and version projections, not content, so a realistic row is small. A wider
/// payload would make the byte probe dominate and measure a backlog this system
/// does not produce.
const PAYLOAD_BYTES: usize = 512;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

/// Bulk-seed `count` pending rows in one statement.
///
/// Deliberately **not** `relay_harness::append_n_pending`, which opens one
/// transaction per row through the production `append()` path. That is the right
/// seed for a behavioral test and the wrong one here: ten thousand round trips
/// would take longer than the drain being measured, and what is under
/// measurement is the *relay*, not the producer.
///
/// Every column is still shaped so `envelope_map::map_event` accepts the row —
/// a non-zero 16-byte repository, a 32-byte aggregate identity, and an 8-byte
/// big-endian ordinal in the F-032-4 v1 encoding, which is exactly what
/// `AggregateVersion::ordinal_only(n).encode()` produces. The first batch's
/// outcomes are asserted below, so a seed that drifted out of that shape fails
/// loudly rather than measuring a drain of rows the relay is rejecting.
async fn seed_pending(url: &str, repository_id: &[u8], count: i64) {
    let client = relay_harness::raw_client(url).await;
    let payload = vec![b'a'; PAYLOAD_BYTES];
    client
        .execute(
            "INSERT INTO lore_outbox_events ( \
                 event_id, cell_id, idempotency_key, \
                 repository_id, repository_generation, \
                 event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                 payload_schema_version, payload, \
                 state, created_at, available_at \
             ) \
             SELECT gen_random_uuid(), $1, sha256(int8send(i)), \
                    $2, 1, \
                    'branch.pushed', 'branch', sha256(int8send(i + 1000000000)), int8send(i), \
                    1, $3, \
                    'pending', clock_timestamp(), clock_timestamp() \
               FROM generate_series(1, $4::bigint) AS i",
            &[
                &relay_harness::TEST_CELL_ID,
                &repository_id,
                &payload,
                &count,
            ],
        )
        .await
        .expect("bulk seed pending outbox rows");
}

/// Drain a seeded backlog and print the rate.
#[tokio::test]
#[ignore = "measurement instrument, not a gate; needs live Postgres (see module docs)"]
async fn measure_relay_drain_rate_against_a_seeded_backlog() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "drain-rate").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();

    let pool = relay_harness::test_pool(&url).await;
    let seed_started = Instant::now();
    seed_pending(&url, &repository_id, SEEDED_ROWS).await;
    let seed_elapsed = seed_started.elapsed();

    let before = {
        let client = pool.get().await.expect("checkout pool client");
        let client: &tokio_postgres::Client = &client;
        backlog(client).await.expect("backlog probe")
    };
    assert_eq!(
        before.pending_count, SEEDED_ROWS,
        "the seed must produce exactly the backlog under measurement"
    );

    let gateway = FakeGateway::accepting();
    let worker = relay_harness::build_worker(pool.clone(), gateway.clone(), "drain-worker");

    let mut drained = 0_u64;
    let mut batches = 0_u64;
    let mut first_batch_elapsed = Duration::ZERO;
    let mut worst_batch_elapsed = Duration::ZERO;
    let started = Instant::now();
    loop {
        let batch_started = Instant::now();
        let claimed = {
            let mut client = pool.get().await.expect("checkout pool client");
            claim_batch(
                &mut client,
                "drain-worker",
                MAX_CLAIM_BATCH,
                Duration::from_secs(30),
            )
            .await
            .expect("claim_batch")
        };
        if claimed.is_empty() {
            break;
        }
        let claimed_rows = claimed.len() as u64;
        for row in claimed {
            let event_id = row.event.event_id;
            let outcome = worker.process_claimed(row).await;
            assert_eq!(
                outcome,
                RowOutcome::Accepted,
                "row {event_id} was not accepted; the seeded row shape has drifted out of what \
                 map_event admits, and this run measures a rejection loop rather than a drain"
            );
        }
        let batch_elapsed = batch_started.elapsed();
        if batches == 0 {
            first_batch_elapsed = batch_elapsed;
        }
        worst_batch_elapsed = worst_batch_elapsed.max(batch_elapsed);
        drained += claimed_rows;
        batches += 1;
    }
    let elapsed = started.elapsed();

    assert_eq!(
        drained, SEEDED_ROWS as u64,
        "every seeded row must drain, or the rate below is over a partial backlog"
    );

    let rows_per_second = drained as f64 / elapsed.as_secs_f64();
    println!("--- WP-119 relay drain rate ---");
    println!("seeded rows          {SEEDED_ROWS}");
    println!("payload bytes/row    {PAYLOAD_BYTES}");
    println!("seed elapsed         {:.3}s", seed_elapsed.as_secs_f64());
    println!("drain elapsed        {:.3}s", elapsed.as_secs_f64());
    println!("batches              {batches} (claim batch {MAX_CLAIM_BATCH})");
    println!(
        "first batch          {:.3}s",
        first_batch_elapsed.as_secs_f64()
    );
    println!(
        "slowest batch        {:.3}s",
        worst_batch_elapsed.as_secs_f64()
    );
    println!("rows/second          {rows_per_second:.0}");
    println!("rows drained in 5s   {:.0}", rows_per_second * 5.0);

    let after = {
        let client = pool.get().await.expect("checkout pool client");
        let client: &tokio_postgres::Client = &client;
        backlog(client).await.expect("backlog probe")
    };
    assert_eq!(
        after.pending_count, 0,
        "the backlog must be empty after the drain"
    );
    println!("-------------------------------");

    namespace.release().await;
}
