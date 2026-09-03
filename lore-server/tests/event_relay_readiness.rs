// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step B: event readiness against a real dead letter, and the
//! admission handle, against CR-032's "Lag, readiness, and backpressure".
//!
//! `readiness.rs`, `admission.rs`, and `retry_info.rs` each already carry a
//! thorough `#[cfg(test)]` module (pure `OutboxBacklog`-driven readiness
//! transitions including the exact-threshold/stale-observation/loop-stopped
//! cases; every `AdmissionRejection` mapping to `RESOURCE_EXHAUSTED` with no
//! leaked observed values; the `RetryInfo` trailer round trip) -- this file
//! does not duplicate any of that. What only a live-Postgres integration
//! test can add: proving `EventRelayReadiness` reflects a REAL dead letter
//! written through Step A's own API and recovers after a real requeue, and
//! proving `OutboxAdmission` actually wires its limits into
//! `relay::admission_check` end to end.

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "common/relay_harness.rs"]
mod relay_harness;

use std::time::Duration;

use case_namespace::CaseNamespace;
use lore_postgres::domain::outbox::AdmissionLimits;
use lore_postgres::domain::outbox::AdmissionRejection;
use lore_postgres::domain::outbox::AdmissionVerdict;
use lore_postgres::domain::outbox::CasOutcome;
use lore_postgres::domain::outbox::DeadLetterOutcome;
use lore_postgres::domain::outbox::relay::admission_check;
use lore_postgres::domain::outbox::relay::backlog;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_postgres::domain::outbox::relay::dead_letter;
use lore_postgres::domain::outbox::relay::requeue_dead_letter;
use lore_server::event_relay::EventRelayReadiness;
use lore_server::event_relay::admission::OutboxAdmission;
use lore_server::event_relay::retry_info::decode_retry_delay;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

// ===========================================================================
// Live: event readiness against a real dead letter
// ===========================================================================

/// Event readiness is false while a real dead letter exists in Postgres,
/// and true again once `requeue_dead_letter` clears it -- proving the
/// probe-and-record path end to end, not only the pure classification
/// `readiness.rs`'s own tests already pin.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn event_readiness_reflects_a_real_dead_letter_and_recovers_after_requeue() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "ready-dlq-live").await;
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
    // The third argument (publish_deadline) is folded into the staleness
    // bound (2 * probe_interval + publish_deadline) since the second
    // reviewer fix round; 10s matches the shipped CR-032 default and this
    // fixture builds no EventRelayConfig of its own to read it from.
    let readiness = EventRelayReadiness::new(
        Duration::from_secs(30),
        Duration::from_secs(5),
        Duration::from_secs(10),
    );
    readiness.set_loop_running(true);

    {
        let mut client = pool.get().await.expect("checkout pool client");
        let claimed = claim_batch(&mut client, "worker-a", 1, Duration::from_secs(30))
            .await
            .expect("claim_batch");
        assert_eq!(claimed.len(), 1);
        let outcome = dead_letter(
            &mut client,
            event_id,
            claimed[0].claim_generation,
            "test_terminal_class",
        )
        .await
        .expect("dead_letter");
        assert!(matches!(outcome, CasOutcome::Applied));
    }

    let raw = relay_harness::raw_client(&url).await;
    let with_dlq = backlog(&raw)
        .await
        .expect("backlog with a dead letter present");
    readiness.record_backlog(&with_dlq);
    assert!(
        !readiness.event_ready(),
        "a live dead letter must make event readiness false"
    );

    let requeued = requeue_dead_letter(
        &mut pool.get().await.expect("checkout pool client"),
        event_id,
        "test requeue",
        "test-operator",
    )
    .await
    .expect("requeue_dead_letter");
    assert!(matches!(requeued, DeadLetterOutcome::Applied));

    let cleared = backlog(&raw).await.expect("backlog after requeue");
    readiness.record_backlog(&cleared);
    assert!(
        readiness.event_ready(),
        "event readiness must recover once the dead letter is requeued"
    );
    namespace.release().await;
}

// ===========================================================================
// Live: the admission handle
// ===========================================================================

fn narrow_limits() -> AdmissionLimits {
    // Small, reachable-at-test-scale limits, injected rather than CR-032's
    // production defaults (1,000,000 rows / 5 GiB), which are not practical
    // to reach in a test.
    AdmissionLimits {
        max_oldest_pending_age: Duration::from_secs(300),
        max_pending_rows: 5,
        max_pending_bytes: 1024,
    }
}

/// `OutboxAdmission` closes on the row-count limit and is open below it,
/// wired through the SAME `relay::admission_check` Step A already
/// unit-tests -- this proves `OutboxAdmission` calls it with the limits it
/// was constructed with, not a hardcoded or narrower set.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_admission_handle_closes_on_pending_rows_over_its_injected_limit() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "admission-rows").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();

    let pool = relay_harness::test_pool(&url).await;
    let admission = OutboxAdmission::new(pool.clone(), narrow_limits());

    let verdict = admission
        .check()
        .await
        .expect("admission check on an empty backlog");
    assert!(
        matches!(verdict, AdmissionVerdict::Admit),
        "empty backlog must admit"
    );

    relay_harness::append_n_pending(&url, &repository_id, 6).await; // over the limit of 5
    let verdict = admission
        .check()
        .await
        .expect("admission check over the row limit");
    match verdict {
        AdmissionVerdict::Reject(AdmissionRejection::PendingRows { observed, limit }) => {
            assert!(observed > limit);
            assert_eq!(limit, 5);
        }
        other => panic!("expected Reject(PendingRows), got {other:?}"),
    }

    // Cross-check the same verdict via the raw Step A function directly, so
    // a drift between OutboxAdmission's own limits and what it passes to
    // admission_check is caught here rather than only by source review.
    let raw = relay_harness::raw_client(&url).await;
    let direct = admission_check(&raw, &narrow_limits())
        .await
        .expect("direct admission_check");
    assert!(matches!(
        direct,
        AdmissionVerdict::Reject(AdmissionRejection::PendingRows { .. })
    ));
    namespace.release().await;
}

/// `OutboxAdmission::check`'s verdict, once rejected, maps through
/// `rejection_status` to `RESOURCE_EXHAUSTED` with a decodable `RetryInfo`
/// delay -- `admission.rs`'s own tests already prove this for every
/// hand-built `AdmissionRejection`; this proves the SAME mapping reached
/// from a real rejection this handle actually produced against live data.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_real_admission_rejection_maps_to_resource_exhausted_with_a_decodable_retry_delay() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "admission-status").await;
    let url = namespace.pg_url().to_owned();
    let repository_id = relay_harness::rand_repository_id();
    relay_harness::append_n_pending(&url, &repository_id, 6).await;

    let pool = relay_harness::test_pool(&url).await;
    let admission = OutboxAdmission::new(pool.clone(), narrow_limits());
    let verdict = admission.check().await.expect("admission check");
    let AdmissionVerdict::Reject(rejection) = verdict else {
        panic!("expected a rejection to build a status from, got {verdict:?}");
    };

    let status = lore_server::event_relay::admission::rejection_status(&rejection);
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    let decoded = decode_retry_delay(status.details());
    assert!(
        decoded.is_some(),
        "a RESOURCE_EXHAUSTED admission rejection must carry a decodable RetryInfo delay"
    );
    namespace.release().await;
}
