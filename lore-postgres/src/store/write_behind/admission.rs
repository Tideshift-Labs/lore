// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Health-aware admission for the staging tier (ADR-00027, "Health-aware
//! operating modes").
//!
//! One snapshot behind an `RwLock`, refreshed by a bounded sampler. Nothing here
//! runs a syscall on the PUT path: a `statvfs` per fragment would put back the
//! per-fragment I/O cost that write-behind exists to remove.
//!
//! Moving a syscall off the PUT path does not make it safe to run anywhere. The
//! sampler's own `stat`/`statvfs` goes to the blocking pool under a bounded
//! wait — `super::sample_within_budget` — because a hung mount must report
//! [`AdmissionSample::RootUnavailable`], not park a runtime worker.
//!
//! # Drain lag is deliberately not an input
//!
//! Staleness of the drain worker's **heartbeat** selects direct fallback,
//! because a cell with no running drain cannot promise to promote what it
//! stages. Drain **lag** does not, and must not: ADR-00027 is explicit that when
//! lag is caused by object-store throttling, direct writes consume the same
//! constrained provider capacity and delay recovery. Oldest-pending age is
//! carried in the snapshot for dashboards and for drain ordering; it never
//! reaches [`Admission::mode`].

use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

/// What a new fragment PUT should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingMode {
    /// Durably stage and acknowledge locally.
    Stage,
    /// Use the existing synchronous object-store path (owner ruling D11).
    DirectFallback,
    /// Return retryable `SlowDown` before exhausting the filesystem.
    Refuse,
    /// Acknowledged staged bytes may exist that this process cannot read. The
    /// cell must not serve, and must not mask the condition with direct writes.
    Unready,
}

/// Operator thresholds, with hysteresis between low and high.
#[derive(Debug, Clone, Copy)]
pub struct WriteBehindWatermarks {
    /// Staged bytes at or below which the tier leaves the elevated state.
    pub low_bytes: u64,
    /// Staged bytes at or above which the tier enters the elevated state and
    /// preserves drain capacity for older fragments.
    pub high_bytes: u64,
    /// Staged bytes at or above which new fragments are refused.
    pub hard_bytes: u64,
    /// Staged fragment count counterparts of the three byte thresholds.
    pub low_count: u64,
    pub high_count: u64,
    pub hard_count: u64,
    /// Free space below which new fragments are refused regardless of
    /// occupancy, so a filesystem shared with anything else cannot be driven to
    /// zero.
    pub min_free_bytes: u64,
}

/// One filesystem observation from the sampler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `Reachable` is constructed only by the `cfg(unix)` sampler. On a platform that
// cannot stage, the root is permanently unavailable and this arm is genuinely
// unreachable, so the allow is conditional: a real dead variant on Unix must
// still warn.
//
// `not(test)` as well as `not(unix)`: this module's own unit tests construct
// the variant on every platform, so the expectation would be unfulfilled — and
// `unfulfilled_lint_expectations` is itself denied — in the test target.
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "staging is Unix-only")
)]
pub(crate) enum AdmissionSample {
    Reachable { free_bytes: u64 },
    RootUnavailable,
}

/// The current admission picture, for metrics and readiness.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionSnapshot {
    pub mode: StagingMode,
    pub staged_bytes: u64,
    pub staged_count: u64,
    pub free_bytes: Option<u64>,
    pub root_available: bool,
    pub drain_healthy: bool,
    /// Whether the tier is in its elevated (high-watermark) state.
    pub elevated: bool,
}

#[derive(Debug)]
struct State {
    staged_bytes: u64,
    staged_count: u64,
    free_bytes: Option<u64>,
    root_available: bool,
    last_heartbeat: Option<Instant>,
    /// Hysteresis latch. Set at the high watermark, cleared at the low one, so
    /// occupancy hovering around one threshold cannot flap the whole cell
    /// between staging and direct writes.
    elevated: bool,
}

/// Shared admission state.
#[derive(Clone)]
pub(crate) struct Admission {
    inner: Arc<RwLock<State>>,
    watermarks: WriteBehindWatermarks,
    drain_stale_after: Duration,
}

impl Admission {
    pub(crate) fn new(watermarks: WriteBehindWatermarks, drain_stale_after: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(State {
                staged_bytes: 0,
                staged_count: 0,
                free_bytes: None,
                // Unknown until the first sample, and unknown reads as
                // unavailable, which is the safe direction.
                //
                // It is not a boot cost, because no PUT is served from this
                // state: `WriteBehindStage::open` takes the first sample
                // synchronously before it returns. That matters more than it
                // looks. The stage starts with `pending_staged` set, so an
                // unknown root there is `Unready` — `SlowDown` on every PUT —
                // not the direct writes an unavailable root alone would give.
                root_available: false,
                last_heartbeat: None,
                elevated: false,
            })),
            watermarks,
            drain_stale_after,
        }
    }

    pub(crate) fn observe_root(&self, sample: AdmissionSample) {
        self.with_state(|state| match sample {
            AdmissionSample::Reachable { free_bytes } => {
                state.root_available = true;
                state.free_bytes = Some(free_bytes);
            }
            AdmissionSample::RootUnavailable => {
                state.root_available = false;
                state.free_bytes = None;
            }
        });
    }

    pub(crate) fn note_drain_heartbeat(&self) {
        self.with_state(|state| state.last_heartbeat = Some(Instant::now()));
    }

    pub(crate) fn note_worker_stopped(&self) {
        self.with_state(|state| state.last_heartbeat = None);
    }

    pub(crate) fn note_occupancy(&self, staged_bytes: u64, staged_count: u64) {
        let watermarks = self.watermarks;
        self.with_state(|state| {
            state.staged_bytes = staged_bytes;
            state.staged_count = staged_count;
            if staged_bytes >= watermarks.high_bytes || staged_count >= watermarks.high_count {
                state.elevated = true;
            } else if staged_bytes <= watermarks.low_bytes && staged_count <= watermarks.low_count {
                state.elevated = false;
            }
        });
    }

    pub(crate) fn root_unavailable(&self) -> bool {
        !self.read(|state| state.root_available)
    }

    pub(crate) fn mode(&self) -> StagingMode {
        self.snapshot().mode
    }

    pub(crate) fn snapshot(&self) -> AdmissionSnapshot {
        let watermarks = self.watermarks;
        let stale_after = self.drain_stale_after;
        self.read(|state| {
            let drain_healthy = state
                .last_heartbeat
                .is_some_and(|beat| beat.elapsed() <= stale_after);
            let refuse = state.staged_bytes >= watermarks.hard_bytes
                || state.staged_count >= watermarks.hard_count
                || state
                    .free_bytes
                    .is_some_and(|free| free < watermarks.min_free_bytes);
            let mode = if !state.root_available {
                // The stage upgrades this to `Unready` when it must assume
                // unreadable acknowledged bytes exist. Admission alone cannot
                // know that: it holds no database resource.
                StagingMode::DirectFallback
            } else if refuse {
                StagingMode::Refuse
            } else if !drain_healthy || state.elevated {
                StagingMode::DirectFallback
            } else {
                StagingMode::Stage
            };
            AdmissionSnapshot {
                mode,
                staged_bytes: state.staged_bytes,
                staged_count: state.staged_count,
                free_bytes: state.free_bytes,
                root_available: state.root_available,
                drain_healthy,
                elevated: state.elevated,
            }
        })
    }

    /// A poisoned admission lock must not take the store down, and must not
    /// silently read as healthy. Both accessors recover the guard and carry on;
    /// the state they protect is advisory occupancy, and the correctness-bearing
    /// refusals live in the coordinator and the confined root.
    fn with_state<T>(&self, update: impl FnOnce(&mut State) -> T) -> T {
        let mut guard = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        update(&mut guard)
    }

    fn read<T>(&self, project: impl FnOnce(&State) -> T) -> T {
        let guard = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        project(&guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watermarks() -> WriteBehindWatermarks {
        WriteBehindWatermarks {
            low_bytes: 100,
            high_bytes: 200,
            hard_bytes: 300,
            low_count: 10,
            high_count: 20,
            hard_count: 30,
            min_free_bytes: 50,
        }
    }

    fn healthy() -> Admission {
        let admission = Admission::new(watermarks(), Duration::from_secs(60));
        admission.observe_root(AdmissionSample::Reachable { free_bytes: 1_000 });
        admission.note_drain_heartbeat();
        admission
    }

    #[test]
    fn a_healthy_tier_stages() {
        assert_eq!(healthy().mode(), StagingMode::Stage);
    }

    #[test]
    fn an_unavailable_root_falls_back_rather_than_refusing() {
        let admission = healthy();
        admission.observe_root(AdmissionSample::RootUnavailable);
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
        assert!(admission.root_unavailable());
    }

    #[test]
    fn a_missing_drain_heartbeat_falls_back() {
        let admission = Admission::new(watermarks(), Duration::from_secs(60));
        admission.observe_root(AdmissionSample::Reachable { free_bytes: 1_000 });
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
    }

    #[test]
    fn a_stale_drain_heartbeat_falls_back() {
        let admission = Admission::new(watermarks(), Duration::ZERO);
        admission.observe_root(AdmissionSample::Reachable { free_bytes: 1_000 });
        admission.note_drain_heartbeat();
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
    }

    #[test]
    fn the_hard_watermark_refuses() {
        let admission = healthy();
        admission.note_occupancy(300, 0);
        assert_eq!(admission.mode(), StagingMode::Refuse);
    }

    #[test]
    fn the_hard_count_refuses_independently_of_bytes() {
        let admission = healthy();
        admission.note_occupancy(0, 30);
        assert_eq!(admission.mode(), StagingMode::Refuse);
    }

    #[test]
    fn low_free_space_refuses_even_when_occupancy_is_small() {
        let admission = healthy();
        admission.observe_root(AdmissionSample::Reachable { free_bytes: 49 });
        admission.note_occupancy(0, 0);
        assert_eq!(admission.mode(), StagingMode::Refuse);
    }

    #[test]
    fn an_unavailable_root_outranks_a_refusal() {
        // A cell that cannot reach its root must fall back, not refuse: refusing
        // would fail clients for a condition direct writes can serve.
        let admission = healthy();
        admission.note_occupancy(300, 30);
        admission.observe_root(AdmissionSample::RootUnavailable);
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
    }

    #[test]
    fn hysteresis_holds_the_elevated_state_between_low_and_high() {
        let admission = healthy();
        admission.note_occupancy(200, 0);
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
        // Below high, above low: still elevated.
        admission.note_occupancy(150, 0);
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
        // At the low watermark: released.
        admission.note_occupancy(100, 0);
        assert_eq!(admission.mode(), StagingMode::Stage);
    }

    #[test]
    fn the_elevated_latch_releases_only_when_both_measures_are_low() {
        let admission = healthy();
        admission.note_occupancy(0, 20);
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
        // Bytes are low but the count is still above its low watermark.
        admission.note_occupancy(0, 15);
        assert_eq!(admission.mode(), StagingMode::DirectFallback);
        admission.note_occupancy(0, 10);
        assert_eq!(admission.mode(), StagingMode::Stage);
    }
}
