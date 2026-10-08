// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_server::event_relay::metrics::*;

/// An `OTel` counter's recorded value cannot be read back here: the meter
/// lives behind a process-global provider cached in a `OnceLock`, so a test
/// can prove the classification but never the emitted number. What it CAN
/// prove is that no label is built by interpolation, which is the property
/// the contract's prohibition actually needs.
#[test]
fn every_label_value_comes_from_the_closed_static_set() {
    for label in [
        CAS_ACCEPT,
        CAS_RETRY,
        CAS_DEAD_LETTER,
        CAS_RENEW,
        CAS_APPLIED,
        CAS_STALE_CLAIM,
        CAS_ALREADY_ACCEPTED,
        CAS_VANISHED,
        ADMISSION_AGE,
        ADMISSION_ROWS,
        ADMISSION_BYTES,
        FAMILY_ACCEPTED,
        CLASS_ACCEPTED,
        DEFERRED_RETRY_POOL,
        DEFERRED_RETRY_WRITE,
        DEFERRED_DEAD_LETTER_POOL,
        DEFERRED_DEAD_LETTER_WRITE,
        BLOCK_CELL_UNKNOWN,
        BLOCK_RESET_IN_PROGRESS,
        BLOCK_NO_PLACEMENT,
        BLOCK_EMPTY_MEMBERSHIP,
        BLOCK_MEMBER_NOT_READY,
        BLOCK_MISSING_CHECKPOINT,
        PRUNED_EVENTS,
        PRUNED_SUPERSEDED,
        PRUNED_DEAD_LETTERS,
        RESET_ACCEPTED,
        RESET_REPLAYED,
        RESET_DETECTION_MISMATCH,
        RESET_PLACEMENT_MISMATCH,
        RESET_STALE_OLD_STREAM,
        RESET_INVALID_SUCCESSOR,
        RESET_CELL_UNKNOWN,
    ] {
        assert!(!label.is_empty());
        assert!(label.is_ascii());
        assert!(!label.contains(' '));
    }
}

#[test]
fn recording_is_infallible_and_never_affects_the_caller() {
    record_claimed_rows(3);
    record_empty_claim();
    record_lease_renewal(CAS_APPLIED);
    record_publish_result("transient", "timeout");
    record_cas_outcome(CAS_ACCEPT, CAS_STALE_CLAIM);
    record_dead_letter("scope_mismatch");
    record_publish_latency_ms(FAMILY_ACCEPTED, 12.5);
    record_deferred(DEFERRED_RETRY_POOL);
    record_backlog(1.0, 2, 0);
    record_admission_rejection(ADMISSION_AGE);
    record_consumer_safe_rows(4);
    record_evaluation_block(BLOCK_RESET_IN_PROGRESS);
    record_pruned_rows(PRUNED_EVENTS, 7);
    record_reset_report(RESET_ACCEPTED);
    record_receiver_lag_rows(3);
}

/// The reset-outcome labels are a closed set that must stay distinct: two
/// outcomes sharing a label would silently merge two different operator
/// signals into one series.
#[test]
fn the_reset_outcome_labels_are_distinct() {
    let mut labels = vec![
        RESET_ACCEPTED,
        RESET_REPLAYED,
        RESET_DETECTION_MISMATCH,
        RESET_PLACEMENT_MISMATCH,
        RESET_STALE_OLD_STREAM,
        RESET_INVALID_SUCCESSOR,
        RESET_CELL_UNKNOWN,
    ];
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total);
}

#[test]
fn the_evaluation_block_labels_are_distinct() {
    let mut labels = vec![
        BLOCK_CELL_UNKNOWN,
        BLOCK_RESET_IN_PROGRESS,
        BLOCK_NO_PLACEMENT,
        BLOCK_EMPTY_MEMBERSHIP,
        BLOCK_MEMBER_NOT_READY,
        BLOCK_MISSING_CHECKPOINT,
    ];
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total);
}

/// The publish-outcome family label set spans four values, and only three
/// of them come from `PublishFailure`. A success recorded under an inline
/// literal would sit outside every check in this file.
#[test]
fn the_publish_family_labels_are_the_three_failure_families_plus_accepted() {
    use lore_server::plugins::remote_notification::NotAcceptedReason;
    use lore_server::plugins::remote_notification::PublishFailure;
    use lore_server::plugins::remote_notification::TerminalClass;
    use lore_server::plugins::remote_notification::TransientClass;

    let mut families = vec![FAMILY_ACCEPTED];
    families.extend(
        [
            PublishFailure::NotAccepted(NotAcceptedReason::UnversionedResponse),
            PublishFailure::Transient(TransientClass::Timeout),
            PublishFailure::Terminal(TerminalClass::ScopeMismatch),
        ]
        .into_iter()
        .map(PublishFailure::family_label),
    );
    let total = families.len();
    families.sort_unstable();
    families.dedup();
    assert_eq!(families.len(), total, "families must be distinct");
    assert_eq!(total, 4);
}
