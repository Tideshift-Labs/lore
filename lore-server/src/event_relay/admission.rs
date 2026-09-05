// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Required-event mutation admission (CR-032 Phase 8).
//!
//! One handle, one question: may this cell accept another mutation that will
//! append an outbox row? The answer comes from **local Postgres facts only** —
//! unpublished row count, unpublished payload bytes, and oldest unpublished
//! age. CR-032 forbids this gate from querying live broker lag, gateway health,
//! or a receiver over the network, and the shape of `relay::admission_check`
//! makes that unrepresentable rather than merely discouraged: nothing reachable
//! from here leaves the database.
//!
//! The gate runs **before** the owning mutation transaction opens. A mutation
//! that already committed stays successful; only a pre-commit rejection exists,
//! and it maps to `RESOURCE_EXHAUSTED` with bounded `RetryInfo`. The server
//! performs no hidden retry of its own.
//!
//! # The mutation path reads a cache, never the database
//!
//! [`OutboxAdmission::check`] is the probe: three bounded but still
//! `O(pending)` queries, which `relay::admission_check`'s own doc comment
//! measures at 19 and 600 shared buffers for 18,000 pending rows. Running that
//! per mutation would put a backlog near the million-row limit in the tens of
//! thousands of buffers on the hot path of every governed write — and it would
//! add a fourth pool borrower contending with the claim loop precisely when the
//! cell is already behind.
//!
//! So the probe runs on the relay worker's readiness tick
//! ([`OutboxAdmission::refresh`], called from the same place that refreshes the
//! backlog observation), and the choke point in
//! [`crate::domain::DomainContext::admit`] reads [`OutboxAdmission::current`],
//! which touches nothing outside this struct. `relay::admission_check`'s doc
//! comment names exactly this shape — "cache the verdict with an explicit
//! bounded staleness rather than widening the limits" — and the bound is the
//! relay's `readiness_probe_interval`.
//!
//! Two consequences, both deliberate:
//!
//! * **Before the first probe the gate is open.** There is no observation, and
//!   an absent observation is not evidence of a backlog. This is the same rule
//!   the probe-error paragraph below states, applied to boot.
//! * **A verdict is not cleared by the mere passage of time.** If the worker
//!   stops refreshing, the last verdict stands. Expiring it on age alone would
//!   silently convert a `Reject` into an admit at exactly the moment nothing is
//!   draining the backlog, which is the wrong direction: a wedged relay is the
//!   case the gate exists for. The relay readiness facet reports the wedge
//!   itself.
//! * **A verdict is cleared by repeated probe failure, in one direction only.**
//!   After [`MAX_PROBE_FAILURES`] consecutive failed refreshes a standing
//!   `Reject` is dropped; a standing `Admit` never is. Without that asymmetry
//!   the paragraph below would be self-contradictory: a database this gate
//!   cannot reach would turn one probe failure into a permanent cell-wide
//!   mutation outage, which is the exact outcome that paragraph forbids. With
//!   it, an unreachable database degrades to the same fail-open posture as a
//!   cell that has never probed, while a reachable one that keeps answering
//!   `Reject` keeps refusing for as long as it answers.
//!
//! # Failing open on a probe error is deliberate
//!
//! If the probe itself fails, this returns the error to the caller rather than
//! guessing. The caller ([`crate::domain::DomainContext::admit`]) then declines
//! to close admission on it, because a backlog probe that cannot run is not
//! evidence of a backlog — and the mutation is about to open its own
//! transaction against the same database, which will fail honestly on its own
//! terms if Postgres is really unreachable. Closing admission here would turn
//! one transient probe failure into a cell-wide mutation outage with a
//! misleading reason.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;

use lore_postgres::domain::DomainError;
use lore_postgres::domain::outbox::AdmissionLimits;
use lore_postgres::domain::outbox::AdmissionRejection;
use lore_postgres::domain::outbox::AdmissionVerdict;
use lore_postgres::domain::outbox::relay;
use lore_postgres::pool::Pool;
use tonic::Status;

use crate::event_relay::metrics;
use crate::event_relay::retry_info;

/// The bounded retry hint attached to a rejection.
///
/// CR-032 requires the `RetryInfo` to be bounded and to fit one measured
/// end-to-end elapsed and attempt budget with the real Lore client policy.
/// WP-119 Phase 8 measured the drain rate this is derived from; it is no longer
/// a placeholder.
///
/// # Two independent floors, and the larger one wins
///
/// **The cache refresh.** This gate does not probe the database per mutation:
/// it reads a verdict the worker's readiness tick refreshes every
/// `readiness_probe_interval`. A client retrying sooner than one whole interval
/// is therefore *guaranteed* to read the identical cached verdict and be
/// refused again for a reason that has not been re-examined. The delay must
/// clear one interval with margin, and
/// [`super::config::EventRelayConfig::from_settings`] enforces the other half
/// of that: a `readiness_probe_interval` at or above this value is a named
/// startup refusal, not a silent inversion.
///
/// **Relay progress.** The retry should also arrive after the relay has had
/// time to change the answer rather than merely to re-report it. Measured
/// (`cargo test -p lore-server --test outbox_drain_rate -- --ignored
/// --nocapture`, PostgreSQL 16 on the local dataplane container, 10,000 seeded
/// pending rows of 512-byte payload, publishing through WP-111's in-process
/// `FakeGateway`, debug build):
///
/// | | |
/// | --- | --- |
/// | drain elapsed | 49.2 s |
/// | rows/second | 203 |
/// | claim batches | 100 at 100 rows |
/// | slowest batch | 4.11 s |
///
/// Ten seconds is more than two of that run's slowest claim-publish-settle
/// batches, so a retry always lands after at least one whole settle cycle. It
/// is also two full readiness intervals *at the shipped five-second default* —
/// though the configuration bound is only `<`, so a cell that widened the probe
/// to nine seconds gets one refresh rather than two. One is the load-bearing
/// claim: it is what makes the retry read a verdict that was re-examined.
///
/// **The measurement's two opposing biases, stated rather than netted.** The
/// fake gateway publishes in-process with no network, which makes 203 rows/s an
/// over-estimate of a production drain; the debug build makes it an
/// under-estimate. Neither is corrected for, because the derivation above does
/// not rest on the rate being accurate — it rests on ten seconds covering
/// several batches at any rate in this neighbourhood, which both biases leave
/// true.
///
/// # The ceiling, against the real client rather than an assumed one
///
/// CR-032 caps the delay by the documented client retry budget: activation is
/// blocked if a generic client's `RESOURCE_EXHAUSTED` retry can exceed it. This
/// paragraph used to reason about "a six-attempt client inside one minute of
/// elapsed time". **No such client ever existed.** The shipped Lore client's
/// `grpc_retry()` (`lore-transport/src/grpc/mod.rs`) is a sixty-attempt client,
/// and WP-119 Phase 8's load proof measured it retrying one refused RPC for 538
/// seconds while never reading this hint at all — nine minutes against a
/// rationale written for one.
///
/// The client now honours the hint (`retry_delay_hint`/`wait_with_hint`, same
/// file), waiting `max(its own backoff step, this delay)` per attempt and
/// counting it as one attempt. So the budget this value implies is arithmetic
/// rather than assumption:
///
/// | | |
/// | --- | --- |
/// | attempts per refused RPC | 60 |
/// | elapsed per refused RPC | 600.0 s to 605.2 s |
///
/// Attempts 1 to 8 have a client backoff step below ten seconds, so this delay
/// dominates at exactly 10 s each (80.0 s). Attempts 9 to 60 sit at the client's
/// own 10 s ceiling plus up to 100 ms of jitter, so the client's step dominates
/// (520.0 s to 525.2 s). It is a **floor**: it counts the waits and not the
/// round trips between them, the client builds a fresh retry per RPC, and no
/// request timeout truncates it.
///
/// **This describes a fork-built client, and not every client is one.** The
/// hint-honouring change lives in our `lore-transport`; a stock Epic-built
/// `lore` CLI does not have it and still runs the unhinted schedule — 538 s over
/// 60 attempts, with its first eight crowded inside 12.75 seconds. So this gate
/// faces two client populations, and the activation reasoning below must not
/// assume the hint is read. What survives either way is the ceiling: 538 s is
/// inside 600 s, so the fork-built client is the worse case and budgeting for it
/// covers both.
///
/// Two consequences worth stating plainly.
///
/// **Honouring the hint made the worst case longer, not shorter** — 600 s where
/// an unhinted client took 538 s. What it bought, for the clients that do read
/// it, is that every retry lands after at least one whole
/// `readiness_probe_interval`, so it reads a verdict that was re-examined. The
/// eight attempts an unhinted client crowds into the first 12.75 seconds are
/// guaranteed to re-read the identical cached refusal.
///
/// **600 seconds per refused RPC is the number CR-032's activation gate has to
/// accept or refuse.** It is not obviously inside any budget; it is merely
/// measured, bounded, and now derived from both halves of the relationship
/// instead of one. Changing this constant changes that budget directly, at 60
/// seconds of client elapsed per second added, so raising it is a reviewed
/// change and not a tuning knob.
///
/// `lore-server/tests/outbox_load_proof.rs`'s
/// `measure_the_real_lore_client_resource_exhausted_retry_budget` pins the
/// client constants, the presence of the hint read, and the absence of a
/// request timeout against `lore-transport`'s source, so a drift on either side
/// trips a test here rather than quietly re-opening this gap.
pub const ADMISSION_RETRY_DELAY: Duration = Duration::from_secs(10);

/// Consecutive failed refreshes after which a standing `Reject` is dropped.
///
/// Small on purpose. At the shipped five-second probe interval this is fifteen
/// seconds of an unreachable database before the gate stops refusing on a
/// verdict it can no longer confirm — long enough that a single hiccup does not
/// reopen a real backlog, short enough that a database outage does not become a
/// mutation outage with a misleading reason. See the module documentation's
/// asymmetry note; this bound applies to `Reject` only.
pub const MAX_PROBE_FAILURES: u32 = 3;

/// The server-side admission handle.
#[derive(Debug, Clone)]
pub struct OutboxAdmission {
    pool: Pool,
    limits: AdmissionLimits,
    /// The last verdict [`OutboxAdmission::refresh`] took and the run of
    /// probe failures since it.
    ///
    /// Shared across clones on purpose: a clone is a second holder of one
    /// cell's gate, not a second gate entitled to its own opinion.
    cached: Arc<Mutex<CachedVerdict>>,
}

/// The cached verdict and the evidence for still trusting it.
///
/// One lock over both, because they are one fact: the failure run is what says
/// whether the verdict beside it may still be enforced, and a reader that saw a
/// fresh verdict with a stale run, or the reverse, would decide on a state no
/// refresh ever produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CachedVerdict {
    verdict: Option<AdmissionVerdict>,
    consecutive_failures: u32,
}

impl CachedVerdict {
    /// A probe answered: that answer is the whole state.
    fn record_success(&mut self, verdict: AdmissionVerdict) {
        self.verdict = Some(verdict);
        self.consecutive_failures = 0;
    }

    /// A probe did not answer. The verdict stands until the failure run reaches
    /// [`MAX_PROBE_FAILURES`], and even then only a `Reject` is dropped — see
    /// the module documentation's asymmetry note.
    fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= MAX_PROBE_FAILURES
            && matches!(self.verdict, Some(AdmissionVerdict::Reject(_)))
        {
            self.verdict = None;
        }
    }
}

impl OutboxAdmission {
    /// Bind the gate to the relay's pool and the cell's reviewed limits.
    pub fn new(pool: Pool, limits: AdmissionLimits) -> Self {
        Self {
            pool,
            limits,
            cached: Arc::new(Mutex::new(CachedVerdict::default())),
        }
    }

    /// The configured limits, for diagnostics and tests.
    pub fn limits(&self) -> &AdmissionLimits {
        &self.limits
    }

    /// Probe local Postgres facts for a fresh verdict.
    ///
    /// This is the database round trip, and it must not run on a mutation
    /// path — see the module documentation. [`Self::refresh`] is the only
    /// caller in the server; the integration tier calls it directly to prove
    /// the limits reach `relay::admission_check` unchanged.
    pub async fn check(&self) -> Result<AdmissionVerdict, DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::Transient(format!("outbox admission pool: {e}")))?;
        relay::admission_check(&**client, &self.limits).await
    }

    /// Take a fresh verdict and publish it to the cache.
    ///
    /// Called from the relay worker's readiness tick, so the cached verdict is
    /// no staler than one `readiness_probe_interval` plus one publish deadline.
    ///
    /// A probe error is returned to the caller to log, and leaves the previous
    /// verdict in place — a probe that could not run is not evidence of a
    /// backlog, and equally not evidence that a backlog cleared. After
    /// [`MAX_PROBE_FAILURES`] consecutive errors a standing `Reject` is
    /// dropped, so an unreachable database cannot hold the gate shut on a
    /// verdict nothing can confirm. A standing `Admit` is never dropped; there
    /// is nothing safer to fall back to than the state a fresh handle is
    /// already in.
    pub async fn refresh(&self) -> Result<AdmissionVerdict, DomainError> {
        match self.check().await {
            Ok(verdict) => {
                self.lock().record_success(verdict.clone());
                Ok(verdict)
            }
            Err(error) => {
                self.lock().record_failure();
                Err(error)
            }
        }
    }

    /// The cached verdict, or `None` before the first successful probe.
    ///
    /// Cache-only by construction: nothing reachable from here touches the
    /// pool, so this cannot become a database round trip on the mutation path
    /// without changing its signature.
    pub fn current(&self) -> Option<AdmissionVerdict> {
        self.lock().verdict.clone()
    }

    /// Consecutive failed refreshes since the last successful one.
    pub fn consecutive_probe_failures(&self) -> u32 {
        self.lock().consecutive_failures
    }

    /// The choke point's whole interaction with this gate.
    ///
    /// `Ok(())` when the cache holds `Admit` or holds nothing yet; `Err` with
    /// the `RESOURCE_EXHAUSTED` status and its bounded `RetryInfo` when the
    /// last probe closed the gate. The rejection metric is recorded here, at
    /// the one place a mutation is actually refused, so the counter measures
    /// refusals rather than probe verdicts.
    pub fn refuse_if_closed(&self) -> Result<(), Status> {
        match self.current() {
            Some(AdmissionVerdict::Reject(rejection)) => {
                metrics::record_admission_rejection(limit_label(&rejection));
                Err(rejection_status(&rejection))
            }
            Some(AdmissionVerdict::Admit) | None => Ok(()),
        }
    }

    /// A panic while holding this lock must not take the gate down with it, and
    /// the guarded value is one plain verdict with no invariant a panic could
    /// have broken halfway. Same rationale as `EventRelayReadiness::lock`.
    fn lock(&self) -> MutexGuard<'_, CachedVerdict> {
        match self.cached.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// The bounded metric label for the limit that tripped.
pub const fn limit_label(rejection: &AdmissionRejection) -> &'static str {
    match rejection {
        AdmissionRejection::OldestPendingAge { .. } => metrics::ADMISSION_AGE,
        AdmissionRejection::PendingRows { .. } => metrics::ADMISSION_ROWS,
        AdmissionRejection::PendingBytes { .. } => metrics::ADMISSION_BYTES,
    }
}

/// The status a closed gate returns to the client.
///
/// The message names the limit that tripped but carries no repository, event,
/// or actor identity: it reaches an unauthenticated-to-this-cell caller, and a
/// backlog is a cell-wide condition rather than anything about the caller's
/// own request.
pub fn rejection_status(rejection: &AdmissionRejection) -> Status {
    let message = match rejection {
        AdmissionRejection::OldestPendingAge { .. } => {
            "This cell is not accepting required-event mutations: the durable event backlog is \
             older than its configured limit"
        }
        AdmissionRejection::PendingRows { .. } => {
            "This cell is not accepting required-event mutations: the durable event backlog \
             exceeds its configured row limit"
        }
        AdmissionRejection::PendingBytes { .. } => {
            "This cell is not accepting required-event mutations: the durable event backlog \
             exceeds its configured byte budget"
        }
    };
    Status::with_details(
        tonic::Code::ResourceExhausted,
        message,
        retry_info::retry_info_details(ADMISSION_RETRY_DELAY, message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
