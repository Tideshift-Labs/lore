// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-114 CD-6's hand-down from WP-118: the periodic terminal write-claim
//! prune scheduler (`lore-server/src/fragment_prune.rs`), proven against real
//! Postgres.
//!
//! `fragment_prune.rs`'s own `#[cfg(test)] mod tests` already pins the
//! readiness/settings state machine from synthetic
//! `FragmentWriteClaimPruneReport` values, and
//! `a_cell_with_no_prune_settings_spawns_nothing` /
//! `enabled_settings_with_no_coordinator_spawn_nothing` already cover the
//! disabled-setting-spawns-no-task leg. This file proves the missing live
//! half: a real terminal claim actually disappears from
//! `lore_fragment_write_claims` within a few ticks, and a claim the prune
//! structurally cannot reach flips the readiness facet false after the
//! configured stall tolerance.
//!
//! # Why a headless hash is the stall fixture
//!
//! `prune_terminal_write_claims`'s plan query is unlocked; the safety
//! guarantee is a head-locked re-check against the hash's
//! `lore_fragment_lifecycle` row (`lore-domain-fragments` skill, "an unlocked
//! filter for progress, a locked probe for safety"). A hash with no lifecycle
//! head row at all has nothing for that re-check to lock, so the loop stops
//! on it rather than proceeding on a lock it never took -- it is examined
//! (the plan query finds it) but never pruned. That is the smallest live
//! reproduction of "the pass makes no progress", without needing a second,
//! genuinely racing writer.

use std::sync::Arc;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use lore_server::fragment_prune::FragmentPruneReadiness;
use lore_server::fragment_prune::FragmentPruneSettings;
use lore_server::fragment_prune::FragmentPruneTask;
use tokio_postgres::Client;

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN")
}

async fn pg_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// A minimal, valid `lore_fragment_lifecycle` head row for `hash`. Any
/// non-{3,4} state satisfies the readable-shape CHECK with `manifest_id`
/// left `NULL`; the prune scheduler only needs the head to exist for its
/// locked re-check, not any particular lifecycle state.
async fn seed_lifecycle_head(client: &Client, hash: &[u8]) {
    client
        .execute(
            "INSERT INTO lore_fragment_lifecycle (hash, current_epoch, state, last_fence) \
             VALUES ($1, 1, 1, 1)",
            &[&hash],
        )
        .await
        .expect("seed a lifecycle head row");
}

/// One already-settled, terminal (state 2 or 4, matching `terminal_prune`'s
/// partial index) write claim on `hash`, aged well past any small retention
/// window this file configures. Field shapes mirror
/// `lore-postgres/tests/domain_fragment_lifecycle.rs`'s
/// `insert_aged_terminal_claim`, with self-contained (not evidence-shared)
/// values: nothing here reads a real fragment, and none of
/// `lore_fragment_write_claims`'s columns are foreign keys.
///
/// `state` must be `2` (Decisive) or `4` (NoSend). A Decisive claim is
/// eligible for deletion only when a matching `lore_fragment_epochs` row
/// exists (`prune_terminal_write_claims`'s plan query `EXISTS` gate) --
/// this fixture never seeds one, so a Decisive claim here is deliberately
/// stuck exactly the way an un-copied-evidence row would be in production
/// (see `fragment_prune.rs`'s own module doc on why the report alone cannot
/// answer "did the pass make progress"). A NoSend claim needs no such
/// evidence and, given a lifecycle head row for its hash, is prunable.
async fn seed_terminal_claim(client: &Client, hash: &[u8], seed: u8, state: i16) {
    let logical_request_id = vec![seed; 16];
    let attempt_id = vec![seed.wrapping_add(1); 16];
    let object_key = format!("wp114-cd6-prune-fixture-{seed:02x}");
    let body_blake3 = vec![seed; 32];
    client
        .execute(
            "INSERT INTO lore_fragment_write_claims ( \
                 logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                 body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at, \
                 authorized_at, settled_at \
             ) VALUES ( \
                 $1, $2, $3, 1, 1, 2, $4, $5, 7, $6, \
                 clock_timestamp() - interval '11 seconds', \
                 clock_timestamp() - interval '10 seconds', \
                 clock_timestamp() - interval '12 seconds', \
                 clock_timestamp() - interval '11 seconds', \
                 clock_timestamp() - interval '9 seconds' \
             )",
            &[
                &logical_request_id,
                &attempt_id,
                &hash,
                &object_key,
                &body_blake3,
                &state,
            ],
        )
        .await
        .expect("seed a terminal write claim");
}

async fn claim_row_exists(client: &Client, hash: &[u8]) -> bool {
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM lore_fragment_write_claims WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("count claim rows")
        .get(0);
    count > 0
}

/// Happy path: with the scheduler enabled and a tiny interval/retention, a
/// terminal write claim on a headed hash disappears within a few ticks, and
/// the readiness facet stays ready throughout.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn a_terminal_claim_on_a_headed_hash_disappears_within_a_few_ticks() {
    let url = pg_url();
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = store.fragment_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install SCHEMA-118 fixture");
    let client = pg_client(&url).await;

    let hash: Vec<u8> = rand::random::<[u8; 32]>().to_vec();
    seed_lifecycle_head(&client, &hash).await;
    seed_terminal_claim(&client, &hash, 0x11, 4).await;
    assert!(
        claim_row_exists(&client, &hash).await,
        "the seeded claim must exist before any pass runs"
    );

    let settings = FragmentPruneSettings::new(Some(1_000), Some(50), Some(1_000), Some(3))
        .expect("bounded settings");
    let readiness = Arc::new(FragmentPruneReadiness::new(&settings));
    let task = FragmentPruneTask::new(coordinator, settings, readiness.clone());

    let mut pruned = false;
    for _ in 0..5 {
        task.prune_once().await;
        if !claim_row_exists(&client, &hash).await {
            pruned = true;
            break;
        }
    }
    assert!(
        pruned,
        "a terminal claim on a headed hash must be pruned within a few ticks"
    );
    assert!(
        readiness.prune_ready(),
        "a scheduler that is making progress must stay ready"
    );
    let snapshot = readiness.snapshot();
    assert!(
        snapshot.last_pruned > 0,
        "the successful pass must be reflected in the facet's own evidence"
    );
}

/// The stall case: a terminal claim on a headless hash is examined by the
/// plan query but can never be pruned (see the module doc). After the
/// configured stall tolerance, the readiness facet must flip false, and the
/// row must remain -- the prune never removes what it cannot lock.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn a_terminal_claim_on_a_headless_hash_flips_readiness_false_after_the_stall_tolerance() {
    let url = pg_url();
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = store.fragment_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install SCHEMA-118 fixture");
    let client = pg_client(&url).await;

    let hash: Vec<u8> = rand::random::<[u8; 32]>().to_vec();
    // Deliberately no `seed_lifecycle_head` call: this hash has no head row,
    // so the locked re-check has nothing to lock and refuses.
    seed_terminal_claim(&client, &hash, 0x21, 2).await;

    let stall_ticks = 2u32;
    let settings =
        FragmentPruneSettings::new(Some(1_000), Some(50), Some(1_000), Some(stall_ticks))
            .expect("bounded settings");
    let readiness = Arc::new(FragmentPruneReadiness::new(&settings));
    let task = FragmentPruneTask::new(coordinator, settings, readiness.clone());

    for _ in 0..stall_ticks {
        task.prune_once().await;
    }
    let snapshot = readiness.snapshot();
    assert!(
        !snapshot.prune_ready,
        "a headless candidate examined but never prunable must flip the facet false \
         after the stall tolerance (consecutive_stalls={})",
        snapshot.consecutive_stalls
    );
    assert!(
        claim_row_exists(&client, &hash).await,
        "a headless claim must never actually be pruned"
    );
}

/// Companion negative to the stall case: the SAME headless-hash claim, run
/// for fewer passes than the stall tolerance, must not yet flip the facet --
/// one skipped batch can be a live write holding a lock elsewhere, matching
/// `fragment_prune.rs`'s own
/// `consecutive_non_progressing_passes_flip_the_facet_after_the_tolerance`
/// unit test, exercised here against the real coordinator instead of a
/// synthetic report.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn one_non_progressing_pass_alone_does_not_yet_flip_readiness() {
    let url = pg_url();
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = store.fragment_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install SCHEMA-118 fixture");
    let client = pg_client(&url).await;

    let hash: Vec<u8> = rand::random::<[u8; 32]>().to_vec();
    seed_terminal_claim(&client, &hash, 0x31, 2).await;

    let settings = FragmentPruneSettings::new(Some(1_000), Some(50), Some(1_000), Some(2))
        .expect("bounded settings; stall_ticks=2");
    let readiness = Arc::new(FragmentPruneReadiness::new(&settings));
    let task = FragmentPruneTask::new(coordinator, settings, readiness.clone());

    task.prune_once().await;
    assert!(
        readiness.prune_ready(),
        "one non-progressing pass must stay within the tolerance"
    );
}
