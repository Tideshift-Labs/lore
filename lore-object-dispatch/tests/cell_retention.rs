// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline, black-box coverage for WP-114 CD-8's cell-scale retention: [`CellRetentionSettings`]'s
//! reviewed bounds, [`CellRetentionReadiness`]'s three-backlog progress rule, and
//! [`CellRetentionClient::new`]'s pool-role guard. No PostgreSQL: `prune_once`/`backlog`/
//! `read_state` need a real dispatch-runtime pool connection and are proven live instead (see
//! `tests/run-cell-retention-live.ps1`).

use std::sync::Arc;
use std::time::Duration;

use lore_object_dispatch::cell_retention::CellRetentionBacklog;
use lore_object_dispatch::cell_retention::CellRetentionClient;
use lore_object_dispatch::cell_retention::CellRetentionPruneReport;
use lore_object_dispatch::cell_retention::CellRetentionReadiness;
use lore_object_dispatch::cell_retention::CellRetentionSettings;
use lore_object_dispatch::cell_retention::CellRetentionSettingsError;
use lore_object_dispatch::cell_retention::MAX_CELL_RETENTION_BATCH;
use lore_object_dispatch::cell_retention::REASON_BACKLOG_SATURATED;
use lore_object_dispatch::cell_retention::REASON_BLOCKED_BACKLOG;
use lore_object_dispatch::cell_retention::REASON_NO_OBSERVATION;
use lore_object_dispatch::cell_retention::REASON_NOT_PROGRESSING;
use lore_object_dispatch::cell_retention::REASON_STALE_OBSERVATION;
use lore_object_dispatch::dispatch_client::DispatchAuthorityError;
use lore_object_dispatch::dispatch_client::DispatchDatabaseIdentity;
use lore_object_dispatch::dispatch_pool::DispatchConnectionBudget;
use lore_object_dispatch::dispatch_pool::DispatchPoolConfig;
use lore_object_dispatch::dispatch_pool::DispatchPoolRole;
use lore_object_dispatch::dispatch_pool::DispatchRuntimePool;
use lore_object_dispatch::dispatch_pool::DispatchTlsMode;

// ---------------------------------------------------------------------------------------------
// 1. CellRetentionSettings::new bounds.
//
// The reviewed bounds themselves (MIN_INTERVAL = 1s, MAX_INTERVAL = 1h, MIN_TERMINAL_RETENTION =
// 60s, MAX_TERMINAL_RETENTION = 7d, MAX_STALL_TICKS = 10) are private to `cell_retention.rs` and
// deliberately not re-exported (only `MAX_CELL_RETENTION_BATCH` is public, since the coordinator
// crate also needs it). The literal millisecond values below are the module's own stated,
// documented bounds, not implementation details this test happens to know.
// ---------------------------------------------------------------------------------------------

const MIN_INTERVAL_MS: u64 = 1_000;
const MAX_INTERVAL_MS: u64 = 60 * 60 * 1_000;
const MIN_TERMINAL_RETENTION_MS: u64 = 60_000;
const MAX_TERMINAL_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAX_STALL_TICKS: u32 = 10;

/// `batch = 10`, so this settings' `probe_limit` (private: `batch.saturating_add(1)`) is 11 --
/// used by the saturation tests below to construct an exactly-saturated backlog without naming the
/// private method.
const TEST_BATCH: u32 = 10;
const TEST_PROBE_LIMIT: i64 = (TEST_BATCH + 1) as i64;

fn settings() -> CellRetentionSettings {
    CellRetentionSettings::new(Some(1_000), Some(TEST_BATCH), Some(600_000), Some(2))
        .expect("bounded settings")
}

#[test]
fn every_value_omitted_takes_its_default() {
    let parsed = CellRetentionSettings::new(None, None, None, None).expect("defaults");
    assert_eq!(parsed, CellRetentionSettings::default());
}

#[test]
fn each_out_of_bounds_value_names_its_own_field() {
    assert_eq!(
        CellRetentionSettings::new(Some(MIN_INTERVAL_MS - 1), None, None, None),
        Err(CellRetentionSettingsError::Interval)
    );
    assert_eq!(
        CellRetentionSettings::new(Some(MAX_INTERVAL_MS + 1), None, None, None),
        Err(CellRetentionSettingsError::Interval)
    );
    assert_eq!(
        CellRetentionSettings::new(None, Some(0), None, None),
        Err(CellRetentionSettingsError::Batch)
    );
    assert_eq!(
        CellRetentionSettings::new(None, Some(MAX_CELL_RETENTION_BATCH + 1), None, None),
        Err(CellRetentionSettingsError::Batch)
    );
    assert_eq!(
        CellRetentionSettings::new(None, None, Some(MIN_TERMINAL_RETENTION_MS - 1), None),
        Err(CellRetentionSettingsError::TerminalRetention)
    );
    assert_eq!(
        CellRetentionSettings::new(None, None, Some(MAX_TERMINAL_RETENTION_MS + 1), None),
        Err(CellRetentionSettingsError::TerminalRetention)
    );
    assert_eq!(
        CellRetentionSettings::new(None, None, None, Some(0)),
        Err(CellRetentionSettingsError::StallTicks)
    );
    assert_eq!(
        CellRetentionSettings::new(None, None, None, Some(MAX_STALL_TICKS + 1)),
        Err(CellRetentionSettingsError::StallTicks)
    );
}

#[test]
fn every_bound_is_inclusive() {
    assert!(CellRetentionSettings::new(Some(MIN_INTERVAL_MS), None, None, None).is_ok());
    assert!(CellRetentionSettings::new(Some(MAX_INTERVAL_MS), None, None, None).is_ok());
    assert!(CellRetentionSettings::new(None, Some(1), None, None).is_ok());
    assert!(CellRetentionSettings::new(None, Some(MAX_CELL_RETENTION_BATCH), None, None).is_ok());
    assert!(CellRetentionSettings::new(None, None, Some(MIN_TERMINAL_RETENTION_MS), None).is_ok());
    assert!(CellRetentionSettings::new(None, None, Some(MAX_TERMINAL_RETENTION_MS), None).is_ok());
    assert!(CellRetentionSettings::new(None, None, None, Some(1)).is_ok());
    assert!(CellRetentionSettings::new(None, None, None, Some(MAX_STALL_TICKS)).is_ok());
}

// ---------------------------------------------------------------------------------------------
// 2. CellRetentionReadiness's three-backlog progress rule.
//
// `record_pass`'s doc names two ways an earlier version of this rule was wrong (both caught by a
// cold review before this shipped): `pruned > 0` must not short-circuit past a saturated backlog,
// and `blocked > 0` must be checked unconditionally, even when rows were removed. Both are worth
// their own discriminating test below rather than trusting the doc's account alone -- a positive
// case proving `blocked > 0` still fails even with `removed > 0`, and one proving saturation still
// fails even with `removed > 0`, are exactly the two shapes a regression back to either earlier
// (wrong) version would need to pass.
// ---------------------------------------------------------------------------------------------

fn report(pruned_requests: i64, pruned_charge_grants: i64) -> CellRetentionPruneReport {
    CellRetentionPruneReport {
        examined: pruned_requests,
        pruned_requests,
        pruned_attempts: pruned_requests,
        pruned_spool_objects: pruned_requests,
        pruned_payload_purges: pruned_requests,
        pruned_fetch_leases: pruned_requests,
        pruned_charge_grants,
        horizon_unix_ms: 1_000,
        database_now_unix_ms: 1_000 + 86_400_000,
    }
}

fn backlog(prunable: i64, blocked: i64, grants: i64) -> CellRetentionBacklog {
    CellRetentionBacklog {
        prunable,
        blocked,
        grants,
        horizon_unix_ms: 1_000,
        database_now_unix_ms: 1_000 + 86_400_000,
    }
}

#[test]
fn a_fresh_facet_is_not_ready() {
    let readiness = CellRetentionReadiness::new(&settings());
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_NO_OBSERVATION));
    assert_eq!(snapshot.last_prunable_backlog, -1);
    assert_eq!(snapshot.last_blocked_backlog, -1);
    assert_eq!(snapshot.last_grant_backlog, -1);
}

/// The goal state: nothing past the horizon at all on any of the three axes. Where a healthy cell
/// sits most of the time.
#[test]
fn an_empty_backlog_is_progress() {
    let readiness = CellRetentionReadiness::new(&settings());
    for _ in 0..5 {
        readiness.record_pass(&report(0, 0), &backlog(0, 0, 0));
    }
    let snapshot = readiness.snapshot();
    assert!(snapshot.retention_ready);
    assert_eq!(snapshot.consecutive_stalls, 0);
    assert_eq!(snapshot.last_prunable_backlog, 0);
    assert_eq!(snapshot.last_blocked_backlog, 0);
    assert_eq!(snapshot.last_grant_backlog, 0);
}

#[test]
fn a_pass_that_removes_rows_is_progress_even_with_a_remaining_unsaturated_backlog() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(4, 0), &backlog(6, 0, 2));
    let snapshot = readiness.snapshot();
    assert!(
        snapshot.retention_ready,
        "a full batch leaves rows behind by design; that is draining, not stalling"
    );
    assert_eq!(snapshot.last_pruned, 4);
    assert_eq!(snapshot.last_prunable_backlog, 6);
    assert_eq!(snapshot.last_grant_backlog, 2);
}

/// `removed` sums the two independent sweeps: a pass that only pruned charge grants (no terminal
/// requests taken) still counts as progress when nothing is blocked and nothing is saturated.
#[test]
fn removed_sums_pruned_requests_and_pruned_charge_grants() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(0, 3), &backlog(0, 0, 2));
    let snapshot = readiness.snapshot();
    assert!(
        snapshot.retention_ready,
        "the grant sweep alone must count as removal"
    );
}

/// The first of the two ways an earlier version of this rule was wrong (per the module's own
/// doc): `blocked > 0` must fail the pass even when rows were removed. A rule that let `removed >
/// 0` short-circuit past this would report a cell with an orphaned spool object as healthy on any
/// tick with traffic -- exactly the case with no other red gate anywhere.
/// `settings()` uses `stall_ticks = 2`, so the facet itself only flips after the tolerance;
/// exceeding it here proves the *reason* it carries is the blocked-backlog cause specifically, not
/// that one blocked pass alone flips the facet (the tolerance test below covers that axis).
#[test]
fn a_nonzero_blocked_backlog_is_never_progress_even_when_rows_were_removed() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(4, 0), &backlog(0, 1, 0));
    readiness.record_pass(&report(4, 0), &backlog(0, 1, 0));
    let snapshot = readiness.snapshot();
    assert!(
        !snapshot.retention_ready,
        "blocked must be checked unconditionally, not skipped because rows were removed"
    );
    assert_eq!(snapshot.retention_reason, Some(REASON_BLOCKED_BACKLOG));
}

/// The second of the two ways: a saturated backlog (>= probe_limit) must fail the pass even when
/// rows were removed. Without this, a cell whose arrivals exceed the drain rate reports green on
/// every tick that happens to remove a full batch, which is every tick.
#[test]
fn a_saturated_prunable_backlog_is_not_progress_even_when_a_full_batch_was_removed() {
    let readiness = CellRetentionReadiness::new(&settings());
    for _ in 0..2 {
        readiness.record_pass(
            &report(i64::from(TEST_BATCH), 0),
            &backlog(TEST_PROBE_LIMIT, 0, 0),
        );
    }
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_BACKLOG_SATURATED));
}

#[test]
fn a_saturated_grant_backlog_alone_is_also_not_progress() {
    let readiness = CellRetentionReadiness::new(&settings());
    for _ in 0..2 {
        readiness.record_pass(&report(0, 0), &backlog(0, 0, TEST_PROBE_LIMIT));
    }
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_BACKLOG_SATURATED));
}

/// Exactly one under the probe limit is still "a full batch remains", not saturation -- the
/// off-by-one this rule exists to get right.
#[test]
fn a_full_but_unsaturated_backlog_with_removal_is_still_progress() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(
        &report(i64::from(TEST_BATCH), 0),
        &backlog(TEST_PROBE_LIMIT - 1, 0, 0),
    );
    assert!(readiness.retention_ready());
}

#[test]
fn a_nonzero_prunable_backlog_below_saturation_with_nothing_removed_is_a_stall() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(0, 0), &backlog(3, 0, 0));
    assert!(readiness.retention_ready(), "one pass is within tolerance");
    readiness.record_pass(&report(0, 0), &backlog(3, 0, 0));
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_NOT_PROGRESSING));
}

#[test]
fn a_nonzero_grant_backlog_alone_below_saturation_with_nothing_removed_is_also_a_stall() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(0, 0), &backlog(0, 0, 2));
    assert!(readiness.retention_ready(), "one pass is within tolerance");
    readiness.record_pass(&report(0, 0), &backlog(0, 0, 2));
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_NOT_PROGRESSING));
}

/// The snapshot surfaces the *last recorded pass's own* stall reason once the tolerance is
/// exceeded, not a generic one -- proven here with the blocked-backlog cause specifically, since a
/// snapshot that only ever reported `REASON_NOT_PROGRESSING` would still pass every test above.
#[test]
fn the_reported_reason_is_the_last_passs_own_cause_not_a_generic_one() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(4, 0), &backlog(0, 1, 0));
    readiness.record_pass(&report(4, 0), &backlog(0, 1, 0));
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_BLOCKED_BACKLOG));
}

#[test]
fn consecutive_non_progressing_passes_flip_the_facet_after_the_tolerance() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(0, 0), &backlog(3, 0, 0));
    assert!(
        readiness.retention_ready(),
        "one non-progressing pass can be a lock held by a live write"
    );
    readiness.record_pass(&report(0, 0), &backlog(3, 0, 0));
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.consecutive_stalls, 2);
}

#[test]
fn a_failed_pass_counts_towards_the_same_tolerance() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_failure();
    readiness.record_failure();
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_NOT_PROGRESSING));
    assert_eq!(
        snapshot.last_prunable_backlog, -1,
        "an unmeasured backlog must not read as an empty one"
    );
    assert_eq!(snapshot.last_blocked_backlog, -1);
    assert_eq!(snapshot.last_grant_backlog, -1);
}

/// The counter is a run length, not a total: one good pass clears it.
#[test]
fn one_progressing_pass_clears_the_stall_run() {
    let readiness = CellRetentionReadiness::new(&settings());
    readiness.record_pass(&report(0, 0), &backlog(3, 0, 0));
    readiness.record_pass(&report(0, 0), &backlog(3, 0, 0));
    assert!(!readiness.retention_ready());
    readiness.record_pass(&report(1, 0), &backlog(2, 0, 0));
    let snapshot = readiness.snapshot();
    assert!(snapshot.retention_ready);
    assert_eq!(snapshot.consecutive_stalls, 0);
}

#[test]
fn every_reason_is_a_bounded_label() {
    for reason in [
        REASON_NO_OBSERVATION,
        REASON_STALE_OBSERVATION,
        REASON_NOT_PROGRESSING,
        REASON_BLOCKED_BACKLOG,
        REASON_BACKLOG_SATURATED,
    ] {
        assert!(!reason.is_empty());
        assert!(reason.is_ascii());
        assert!(!reason.contains(' '));
    }
}

/// The wedged-task case: a healthy observation that stopped being refreshed. Proven with the
/// module's own smallest configurable interval (1s, so a 2s staleness bound) and a real sleep,
/// since the private `staleness_bound` field this crate's own co-located tests could zero out is
/// unreachable from a black-box `tests/` file.
#[test]
fn a_stale_observation_fails_the_facet_even_though_it_looked_healthy() {
    let short_interval = CellRetentionSettings::new(Some(MIN_INTERVAL_MS), None, None, None)
        .expect("minimum interval validates");
    let readiness = CellRetentionReadiness::new(&short_interval);
    readiness.record_pass(&report(10, 0), &backlog(0, 0, 0));
    assert!(readiness.retention_ready(), "just recorded, must be fresh");
    std::thread::sleep(Duration::from_millis(2 * MIN_INTERVAL_MS + 250));
    let snapshot = readiness.snapshot();
    assert!(!snapshot.retention_ready);
    assert_eq!(snapshot.retention_reason, Some(REASON_STALE_OBSERVATION));
}

// ---------------------------------------------------------------------------------------------
// 3. CellRetentionClient::new's pool-role guard.
//
// `DispatchRuntimePool::new` validates configuration and opens no connection, so the role guard is
// provable offline. `prune_once`/`backlog`/`read_state` need a real connection and stay live-only.
// ---------------------------------------------------------------------------------------------

fn pool_config(role: DispatchPoolRole) -> DispatchPoolConfig {
    DispatchPoolConfig {
        postgres_url: format!(
            "postgresql://{}@127.0.0.1:1/unused?sslmode=disable",
            role.role_name()
        ),
        role,
        expected_database_identity: DispatchDatabaseIdentity::new(1, 1)
            .expect("nonzero identity for the offline role-guard fixture"),
        pool_max: 1,
        connect_timeout: Duration::from_secs(1),
        acquire_timeout: Duration::from_secs(1),
        statement_timeout: Duration::from_millis(250),
        lock_timeout: Duration::from_millis(250),
        tls: DispatchTlsMode::Disabled,
        budget: DispatchConnectionBudget::new(1, 1, 1, 1, 1)
            .expect("minimal process budget for the offline role-guard fixture"),
    }
}

#[test]
fn cell_retention_client_new_refuses_a_maintenance_role_pool() {
    let pool = DispatchRuntimePool::new(pool_config(DispatchPoolRole::Maintenance))
        .expect("valid offline pool configuration");
    assert_eq!(
        CellRetentionClient::new(Arc::new(pool)).err(),
        Some(DispatchAuthorityError::WrongPoolRole)
    );
}

#[test]
fn cell_retention_client_new_accepts_a_runtime_role_pool() {
    let pool = DispatchRuntimePool::new(pool_config(DispatchPoolRole::Runtime))
        .expect("valid offline pool configuration");
    assert!(CellRetentionClient::new(Arc::new(pool)).is_ok());
}
