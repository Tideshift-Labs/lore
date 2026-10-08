// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;

use lore_postgres::domain::outbox::AdmissionRejection;
use lore_postgres::domain::outbox::AdmissionVerdict;
use lore_server::event_relay::admission::*;
use lore_server::event_relay::retry_info;

fn rejections() -> Vec<AdmissionRejection> {
    vec![
        AdmissionRejection::OldestPendingAge {
            observed: Duration::from_secs(600),
            limit: Duration::from_secs(300),
        },
        AdmissionRejection::PendingRows {
            observed: 1_000_001,
            limit: 1_000_000,
        },
        AdmissionRejection::PendingBytes {
            observed: 6 * 1024 * 1024 * 1024,
            limit: 5 * 1024 * 1024 * 1024,
        },
    ]
}

#[test]
fn every_rejection_is_resource_exhausted_with_a_readable_retry_delay() {
    for rejection in rejections() {
        let status = rejection_status(&rejection);
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            retry_info::decode_retry_delay(status.details()),
            Some(ADMISSION_RETRY_DELAY),
            "every rejection must carry a bounded RetryInfo"
        );
    }
}

/// The message reaches a client, so it must not leak the observed backlog
/// numbers of a cell serving other tenants.
#[test]
fn a_rejection_message_carries_no_observed_values() {
    for rejection in rejections() {
        let status = rejection_status(&rejection);
        let message = status.message();
        for leaked in ["1000001", "600", "6442450944"] {
            assert!(
                !message.contains(leaked),
                "message leaked an observed value: {message}"
            );
        }
    }
}

/// A cell that has never probed admits. There is no observation, and an
/// absent observation is not evidence of a backlog.
#[test]
fn a_cache_with_no_verdict_admits() {
    let cached = CachedVerdict::default();
    assert_eq!(cached.verdict, None);
    assert_eq!(cached.consecutive_failures, 0);
}

/// The gate must keep refusing while the database keeps saying so. Time
/// alone never reopens it.
#[test]
fn a_reject_stands_through_fewer_failures_than_the_bound() {
    let mut cached = CachedVerdict::default();
    cached.record_success(AdmissionVerdict::Reject(rejections().remove(0)));
    for _ in 0..(MAX_PROBE_FAILURES - 1) {
        cached.record_failure();
        assert!(
            matches!(cached.verdict, Some(AdmissionVerdict::Reject(_))),
            "a single probe hiccup must not reopen a real backlog"
        );
    }
}

/// The asymmetry the module documents: a database this gate cannot reach
/// must not become a permanent cell-wide mutation outage.
#[test]
fn a_reject_is_dropped_once_the_failure_run_reaches_the_bound() {
    let mut cached = CachedVerdict::default();
    cached.record_success(AdmissionVerdict::Reject(rejections().remove(0)));
    for _ in 0..MAX_PROBE_FAILURES {
        cached.record_failure();
    }
    assert_eq!(
        cached.verdict, None,
        "an unconfirmable Reject must degrade to the never-probed state"
    );
    // And it stays there rather than wrapping or resurrecting.
    cached.record_failure();
    assert_eq!(cached.verdict, None);
}

/// Only `Reject` is dropped. There is nothing safer than `Admit` to fall
/// back to, so dropping it would be churn with no meaning.
#[test]
fn an_admit_is_never_dropped_by_probe_failures() {
    let mut cached = CachedVerdict::default();
    cached.record_success(AdmissionVerdict::Admit);
    for _ in 0..(MAX_PROBE_FAILURES * 4) {
        cached.record_failure();
    }
    assert_eq!(cached.verdict, Some(AdmissionVerdict::Admit));
}

/// One answering probe clears the run: the bound is a run length, not a
/// total.
#[test]
fn a_successful_probe_clears_the_failure_run() {
    let mut cached = CachedVerdict::default();
    cached.record_success(AdmissionVerdict::Reject(rejections().remove(0)));
    cached.record_failure();
    cached.record_failure();
    cached.record_success(AdmissionVerdict::Reject(rejections().remove(0)));
    assert_eq!(cached.consecutive_failures, 0);
    cached.record_failure();
    assert!(
        matches!(cached.verdict, Some(AdmissionVerdict::Reject(_))),
        "the run restarted, so one failure is nowhere near the bound"
    );
}

#[test]
fn each_limit_maps_to_a_distinct_bounded_label() {
    let mut labels: Vec<&'static str> = rejections().iter().map(limit_label).collect();
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total);
}
