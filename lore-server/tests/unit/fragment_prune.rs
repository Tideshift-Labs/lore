// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `fragment_prune` tests, moved out of the inline
//! `tests` module when upstream set `[lib] test = false`.

use std::sync::Mutex;
use std::time::Duration;

use lore_postgres::domain::fragments::FragmentWriteClaimPruneBatch;
use lore_postgres::domain::fragments::FragmentWriteClaimPruneReport;
use lore_postgres::domain::fragments::MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH;
use lore_server::fragment_prune::*;
use tokio::sync::watch;
use tokio::task::JoinSet;

fn report(examined: u64, pruned: u64) -> FragmentWriteClaimPruneReport {
    FragmentWriteClaimPruneReport {
        examined,
        pruned,
        skipped_blocked: examined - pruned,
        skipped_missing_evidence: 0,
    }
}

fn settings() -> FragmentPruneSettings {
    FragmentPruneSettings::new(Some(1_000), Some(10), Some(60_000), Some(2))
        .expect("bounded settings")
}

#[test]
fn every_value_omitted_takes_its_default() {
    let parsed = FragmentPruneSettings::new(None, None, None, None).expect("defaults");
    assert_eq!(parsed, FragmentPruneSettings::default());
}

#[test]
fn each_out_of_bounds_value_names_its_own_field() {
    assert_eq!(
        FragmentPruneSettings::new(Some(999), None, None, None),
        Err(FragmentPruneSettingsError::Interval)
    );
    assert_eq!(
        FragmentPruneSettings::new(None, Some(0), None, None),
        Err(FragmentPruneSettingsError::Batch)
    );
    assert_eq!(
        FragmentPruneSettings::new(
            None,
            Some(MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH + 1),
            None,
            None
        ),
        Err(FragmentPruneSettingsError::Batch)
    );
    assert_eq!(
        FragmentPruneSettings::new(None, None, Some(0), None),
        Err(FragmentPruneSettingsError::TerminalRetention)
    );
    assert_eq!(
        FragmentPruneSettings::new(None, None, None, Some(0)),
        Err(FragmentPruneSettingsError::StallTicks)
    );
    assert_eq!(
        FragmentPruneSettings::new(None, None, None, Some(MAX_STALL_TICKS + 1)),
        Err(FragmentPruneSettingsError::StallTicks)
    );
}

/// The bound the task actually relies on: a settings value can never be
/// rejected by the coordinator it was validated against.
#[test]
fn a_validated_batch_is_always_accepted_by_the_coordinator() {
    for batch in [1, DEFAULT_BATCH, MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH] {
        let parsed = FragmentPruneSettings::new(None, Some(batch), None, None)
            .expect("a bounded batch validates");
        assert!(FragmentWriteClaimPruneBatch::new(parsed.batch, parsed.terminal_retention).is_ok());
    }
}

#[test]
fn a_fresh_facet_is_not_ready() {
    let readiness = FragmentPruneReadiness::new(&settings());
    let snapshot = readiness.snapshot();
    assert!(!snapshot.prune_ready);
    assert_eq!(snapshot.prune_reason, Some(REASON_NO_OBSERVATION));
}

/// The retention bound is checked too, not only the batch.
#[test]
fn a_validated_retention_is_always_accepted_by_the_coordinator() {
    for millis in [1, 60_000, MAX_TERMINAL_RETENTION.as_millis() as u64] {
        let parsed = FragmentPruneSettings::new(None, None, Some(millis), None)
            .expect("a bounded retention validates");
        assert!(
            FragmentWriteClaimPruneBatch::new(parsed.batch, parsed.terminal_retention).is_ok(),
            "retention {millis} ms validated here but was rejected by the coordinator"
        );
    }
}

/// The goal state: nothing past retention that is not transiently blocked.
/// This is where a healthy cell sits most of the time.
#[test]
fn an_empty_backlog_is_progress() {
    let readiness = FragmentPruneReadiness::new(&settings());
    for _ in 0..5 {
        readiness.record_pass(&report(0, 0), 0);
    }
    let snapshot = readiness.snapshot();
    assert!(snapshot.prune_ready);
    assert_eq!(snapshot.consecutive_stalls, 0);
    assert_eq!(snapshot.last_unblocked_backlog, 0);
}

#[test]
fn a_pass_that_removes_rows_is_progress_even_with_a_remaining_backlog() {
    let readiness = FragmentPruneReadiness::new(&settings());
    readiness.record_pass(&report(10, 4), 11);
    let snapshot = readiness.snapshot();
    assert!(
        snapshot.prune_ready,
        "a full batch leaves rows behind by design; that is draining, not stalling"
    );
    assert_eq!(snapshot.last_pruned, 4);
    assert_eq!(snapshot.last_examined, 10);
    assert_eq!(snapshot.last_unblocked_backlog, 11);
}

/// The finding this rule exists for: the plan query returns nothing while
/// rows sit past retention, because their epoch evidence was never copied.
/// Keyed on `examined` this reports green forever.
#[test]
fn an_empty_plan_over_a_non_empty_backlog_is_a_stall_not_a_drained_table() {
    let readiness = FragmentPruneReadiness::new(&settings());
    readiness.record_pass(&report(0, 0), 2);
    assert!(readiness.prune_ready(), "one pass is within tolerance");
    readiness.record_pass(&report(0, 0), 2);
    let snapshot = readiness.snapshot();
    assert!(!snapshot.prune_ready);
    assert_eq!(snapshot.prune_reason, Some(REASON_NOT_PROGRESSING));
    assert_eq!(snapshot.last_examined, 0);
    assert_eq!(snapshot.last_unblocked_backlog, 2);
}

/// The head-of-line shape INV-FJ fixed: candidates found, none removed.
/// One pass is tolerated, `stall_ticks` consecutive ones are not.
#[test]
fn consecutive_non_progressing_passes_flip_the_facet_after_the_tolerance() {
    let readiness = FragmentPruneReadiness::new(&settings());
    readiness.record_pass(&report(10, 0), 10);
    assert!(
        readiness.prune_ready(),
        "one skipped batch can be a live write holding a lock"
    );
    readiness.record_pass(&report(10, 0), 10);
    let snapshot = readiness.snapshot();
    assert!(!snapshot.prune_ready);
    assert_eq!(snapshot.prune_reason, Some(REASON_NOT_PROGRESSING));
    assert_eq!(snapshot.consecutive_stalls, 2);
}

#[test]
fn a_failed_pass_counts_towards_the_same_tolerance() {
    let readiness = FragmentPruneReadiness::new(&settings());
    readiness.record_failure();
    readiness.record_failure();
    let snapshot = readiness.snapshot();
    assert!(!snapshot.prune_ready);
    assert_eq!(snapshot.prune_reason, Some(REASON_NOT_PROGRESSING));
    assert_eq!(
        snapshot.last_unblocked_backlog, -1,
        "an unmeasured backlog must not read as an empty one"
    );
}

/// The counter is a run length, not a total: one good pass clears it.
#[test]
fn one_progressing_pass_clears_the_stall_run() {
    let readiness = FragmentPruneReadiness::new(&settings());
    readiness.record_pass(&report(10, 0), 10);
    readiness.record_pass(&report(10, 0), 10);
    assert!(!readiness.prune_ready());
    readiness.record_pass(&report(10, 1), 9);
    let snapshot = readiness.snapshot();
    assert!(snapshot.prune_ready);
    assert_eq!(snapshot.consecutive_stalls, 0);
}

/// The wedged-task case: a healthy observation that stopped being
/// refreshed. A zero staleness bound makes any elapsed time stale, which is
/// how this is provable without sleeping.
#[test]
fn a_stale_observation_fails_the_facet_even_though_it_looked_healthy() {
    let readiness = FragmentPruneReadiness {
        state: Mutex::new(PruneState::default()),
        stall_ticks: 3,
        staleness_bound: Duration::ZERO,
    };
    readiness.record_pass(&report(10, 10), 0);
    while readiness.snapshot().observation_age == Some(Duration::ZERO) {
        std::hint::spin_loop();
    }
    let snapshot = readiness.snapshot();
    assert!(!snapshot.prune_ready);
    assert_eq!(snapshot.prune_reason, Some(REASON_STALE_OBSERVATION));
}

#[test]
fn every_reason_is_a_bounded_label() {
    for reason in [
        REASON_NO_OBSERVATION,
        REASON_STALE_OBSERVATION,
        REASON_NOT_PROGRESSING,
    ] {
        assert!(!reason.is_empty());
        assert!(reason.is_ascii());
        assert!(!reason.contains(' '));
    }
}

/// No settings means no task and no facet: an unconfigured cell must not
/// report a green prune it is not running.
#[test]
fn a_cell_with_no_prune_settings_spawns_nothing() {
    let mut endpoints = JoinSet::new();
    let (_tx, shutdown) = watch::channel(false);
    let readiness = configure_fragment_prune(None, None, &mut endpoints, shutdown);
    assert!(readiness.is_none());
    assert!(endpoints.is_empty());
}

/// Enabled settings with no coordinator must not silently start a
/// scheduler-shaped nothing.
#[test]
fn enabled_settings_with_no_coordinator_spawn_nothing() {
    let mut endpoints = JoinSet::new();
    let (_tx, shutdown) = watch::channel(false);
    let readiness = configure_fragment_prune(None, Some(settings()), &mut endpoints, shutdown);
    assert!(readiness.is_none());
    assert!(endpoints.is_empty());
}
