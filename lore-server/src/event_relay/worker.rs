// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The bounded relay loop (CR-032 Phase 5; WP-119 Step B).
//!
//! One loop per Postgres-mode loreserver. There is no elected leader: several
//! workers claim disjoint batches through `FOR UPDATE SKIP LOCKED`, and a
//! per-row monotonic `claim_generation` fences a worker whose lease was
//! reclaimed out of acknowledging, rescheduling, or dead-lettering the newer
//! claim.
//!
//! # The two invariants the shape of this file exists to hold
//!
//! **No pooled connection, transaction, or row lock is held across a publish.**
//! The claim transaction commits and its client is returned to the pool
//! *before* the first envelope leaves the process. Each later database write
//! checks a connection back out for the duration of one statement. That costs a
//! pool round trip per row and buys the property CR-032 makes non-negotiable:
//! a gateway that stops answering cannot pin a Postgres connection, and no
//! amount of broker latency can exhaust the pool.
//!
//! **No row blocks the rows behind it.** Every per-row outcome — accepted,
//! requeued, dead-lettered, fenced out, deferred — settles that row within the
//! batch, and the loop moves to the next one. A row that cannot be represented
//! as an envelope is dead-lettered on its first attempt, because the failure is
//! a deterministic property of the row.
//!
//! A gateway rejection is not. CR-032 makes invalid scope and unsupported
//! schema terminal outright but a bare event-specific 4xx terminal only when
//! **repeated**, and [`EventRelayWorker::terminal_is_final`] holds that line:
//! without it, one version-skewed gateway drains a cell's whole backlog into
//! dead letters at a batch per iteration, each row then needing a manual
//! operator disposition to come back.
//!
//! # What this loop deliberately does not do
//!
//! It never advances `consumer_safe`, never infers consumer safety from a
//! broker acknowledgement, and never fabricates an acceptance from a timeout.
//! A response that does not prove acceptance leaves the row pending with its
//! original stable keys, which is the whole reason `PublishFailure::NotAccepted`
//! is a separate family from `Terminal`.

use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use lore_postgres::domain::DomainError;
use lore_postgres::domain::outbox::BrokerAcceptanceRecord;
use lore_postgres::domain::outbox::CasOutcome;
use lore_postgres::domain::outbox::ClaimedEvent;
use lore_postgres::domain::outbox::relay;
use lore_postgres::pool::Pool;
use tokio::sync::watch;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::event_relay::admission::OutboxAdmission;
use crate::event_relay::config::EventRelayConfig;
use crate::event_relay::envelope_map::EnvelopeSource;
use crate::event_relay::envelope_map::map_event;
use crate::event_relay::metrics;
use crate::event_relay::publisher::DurablePublisher;
use crate::event_relay::readiness::EventRelayReadiness;
use crate::plugins::remote_notification::BrokerAcceptance;
use crate::plugins::remote_notification::PublishFailure;
use crate::plugins::remote_notification::TerminalClass;

/// What happened to one claimed row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowOutcome {
    /// The gateway accepted it and the row is now `broker_accepted`.
    Accepted,
    /// Transient or unproven: the row is pending again with a later
    /// `available_at` and its original keys.
    Requeued,
    /// Terminally failed: the row moved to the dead-letter table.
    DeadLettered,
    /// A newer claim owns the row. This worker dropped it without writing.
    Fenced,
    /// The row was already past `pending` when this worker tried to record its
    /// acceptance: another attempt published it first.
    Duplicate,
    /// A database write failed and could not be rescheduled either. The row
    /// keeps its claim until the lease expires, then becomes claimable again.
    ///
    /// Every path that reaches this has already tried to advance the row's
    /// `attempt_count` and `available_at` and failed, so it means the database
    /// is unreachable rather than that the relay chose to wait.
    Deferred,
}

/// Whether this worker still holds the claim it is about to publish under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseState {
    /// The lease is current, either already or after a successful renewal.
    Held,
    /// A compare-and-set proved a newer claim owns the row.
    Lost,
    /// The database could not be reached, so neither answer is proven.
    Unknown,
}

/// Class for a gateway acceptance the store cannot represent.
///
/// Not terminal on sight. All three values that can overflow — broker sequence,
/// stream epoch, publisher contract version — are properties of the *stream or
/// gateway*, not of this event, so one misbehaving gateway would otherwise
/// dead-letter the whole backlog. Worse than the ordinary mass-dead-letter
/// case, because every one of those rows *was* published: each dead letter
/// would also be a broker duplicate.
const ACCEPTANCE_OUT_OF_RANGE: &str = "acceptance_evidence_out_of_range";
/// Retry class for a publish that succeeded and whose row update did not.
const ACCEPT_WRITE_FAILED: &str = "accept_write_failed";
/// Retry class for a lease renewal that could not reach the database.
const LEASE_RENEWAL_FAILED: &str = "lease_renewal_failed";

/// The bounded relay worker.
pub struct EventRelayWorker {
    pool: Pool,
    publisher: Arc<dyn DurablePublisher>,
    config: EventRelayConfig,
    readiness: Arc<EventRelayReadiness>,
    source: EnvelopeSource,
    admission: Option<Arc<OutboxAdmission>>,
}

impl EventRelayWorker {
    /// Assemble a worker. Nothing runs until [`EventRelayWorker::run`].
    pub fn new(
        pool: Pool,
        publisher: Arc<dyn DurablePublisher>,
        config: EventRelayConfig,
        readiness: Arc<EventRelayReadiness>,
        source: EnvelopeSource,
    ) -> Self {
        Self {
            pool,
            publisher,
            config,
            readiness,
            source,
            admission: None,
        }
    }

    /// Refresh this admission gate's cached verdict on the readiness tick.
    ///
    /// Optional so a component test can run the loop without one. In the
    /// server it is always set: `wiring` builds the gate and the worker
    /// together, and the mutation choke point reads a cache nothing else in
    /// the process refreshes.
    #[must_use]
    pub fn with_admission(mut self, admission: Arc<OutboxAdmission>) -> Self {
        self.admission = Some(admission);
        self
    }

    /// Run until `shutdown` goes true.
    ///
    /// The loop returns `Ok(())` on drain. It returns an error only for a fault
    /// that cannot be retried into progress, because this task is spawned into
    /// the server's endpoint `JoinSet` and an error there takes the process
    /// down. A pool failure or a failed claim is emphatically not that: it is
    /// logged, counted through the readiness facet going stale, and retried
    /// after the idle interval.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        info!(
            owner = %self.config.owner,
            batch_size = self.config.batch_size,
            lease_seconds = self.config.claim_lease.as_secs(),
            "Starting the CR-032 outbox relay worker"
        );
        self.readiness.set_loop_running(true);
        let mut next_probe = tokio::time::Instant::now();

        loop {
            if *shutdown.borrow() {
                break;
            }

            if tokio::time::Instant::now() >= next_probe {
                self.refresh_backlog().await;
                next_probe = tokio::time::Instant::now() + self.config.readiness_probe_interval;
            }

            let claimed = match self.claim().await {
                Ok(claimed) => claimed,
                Err(e) => {
                    // Deliberately not fatal: a transient pool or database
                    // failure must not take the whole loreserver down, and the
                    // relay facet goes stale on its own while this repeats.
                    warn!(error = %e, "Outbox relay claim failed; retrying after the idle interval");
                    if self
                        .sleep_or_shutdown(self.config.idle_interval, &mut shutdown)
                        .await
                    {
                        break;
                    }
                    continue;
                }
            };

            if claimed.is_empty() {
                metrics::record_empty_claim();
                if self
                    .sleep_or_shutdown(self.config.idle_interval, &mut shutdown)
                    .await
                {
                    break;
                }
                continue;
            }

            metrics::record_claimed_rows(claimed.len() as u64);
            debug!(rows = claimed.len(), "Outbox relay claimed a batch");

            for row in claimed {
                // Drain stops mid-batch, after the row in flight settles.
                //
                // CR-032's drain requirement is to stop claiming, bound
                // accepted work, and leave uncompleted claims reclaimable — and
                // an unstarted row in this batch is exactly a reclaimable
                // uncompleted claim, so abandoning it costs one lease period
                // and nothing else. Running the whole batch out would not:
                // `batch_size` publishes at the publish deadline is over
                // sixteen minutes at the shipped defaults, and a cell with
                // `graceful_drain` on and no drain timeout has no backstop that
                // would cut it short.
                if *shutdown.borrow() {
                    info!(
                        "Outbox relay draining: abandoning the rest of this batch to their leases"
                    );
                    break;
                }

                // Probed inside the batch, not only between batches. A batch can
                // run far longer than the probe interval, and a readiness
                // observation that only refreshes between batches would age past
                // its own staleness bound on a busy but perfectly healthy relay
                // — reporting a lag incident that is really just a long batch.
                if tokio::time::Instant::now() >= next_probe {
                    self.refresh_backlog().await;
                    next_probe = tokio::time::Instant::now() + self.config.readiness_probe_interval;
                }

                let outcome = self.process_claimed(row).await;
                debug!(?outcome, "Outbox relay row settled");
            }
        }

        self.readiness.set_loop_running(false);
        info!("Outbox relay worker drained: no further claims will be taken");
        Ok(())
    }

    /// One claim transaction, with the pooled client released before returning.
    async fn claim(&self) -> Result<Vec<ClaimedEvent>, DomainError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::Transient(format!("outbox relay claim pool: {e}")))?;
        relay::claim_batch(
            &mut client,
            &self.config.owner,
            self.config.batch_size,
            self.config.claim_lease,
        )
        .await
    }

    /// Refresh the backlog facts readiness reports, and the admission verdict
    /// the mutation choke point reads.
    ///
    /// The two are refreshed on one tick because they answer the same question
    /// from the same table at the same bounded staleness, and because this is
    /// the only place in the process allowed to pay for the probe: CR-032's
    /// gate must not put a bounded-but-`O(pending)` query on the hot path of
    /// every governed mutation. See `admission`'s module documentation.
    async fn refresh_backlog(&self) {
        self.refresh_admission().await;
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                warn!(error = %e, "Outbox relay backlog probe could not check out a connection");
                return;
            }
        };
        match relay::backlog(&**client).await {
            // A failed probe records nothing, so the previous observation ages
            // out and the facet fails closed. Recording a fabricated healthy
            // observation here would be the one way to make the readiness
            // signal actively lie.
            Err(e) => warn!(error = %e, "Outbox relay backlog probe failed"),
            Ok(backlog) => {
                if backlog.saturated() {
                    warn!(
                        pending_count = backlog.pending_count,
                        "Outbox backlog probe saturated: the real backlog is larger than reported"
                    );
                }
                self.readiness.record_backlog(&backlog);
            }
        }
    }

    /// Republish the admission verdict, if this worker carries the gate.
    ///
    /// A probe failure is logged and leaves the previous verdict standing, on
    /// the same reasoning as the backlog probe above: a probe that could not
    /// run is evidence of nothing, in either direction.
    async fn refresh_admission(&self) {
        let Some(admission) = self.admission.as_ref() else {
            return;
        };
        if let Err(e) = admission.refresh().await {
            warn!(error = %e, "Outbox admission probe failed; the previous verdict stands");
        }
    }

    /// Take one claimed row from claim to a durable outcome.
    ///
    /// Public so a component test can drive exactly one row without running the
    /// loop, which is the only way to assert an outcome without racing the
    /// idle interval.
    pub async fn process_claimed(&self, mut claimed: ClaimedEvent) -> RowOutcome {
        let event_id = claimed.event.event_id;
        let claim_generation = claimed.claim_generation;

        let envelope = match map_event(&claimed.event, &self.source, SystemTime::now()) {
            Ok(envelope) => envelope,
            Err(failure) => {
                // A row that cannot be represented will fail identically on
                // every future attempt, so it is terminal on its first one.
                error!(
                    event_id = %event_id,
                    class = failure.as_terminal_class(),
                    error = %failure,
                    "Outbox row cannot be mapped to a durable envelope; dead-lettering"
                );
                return self
                    .dead_letter(event_id, claim_generation, failure.as_terminal_class())
                    .await;
            }
        };

        match self.ensure_lease(&mut claimed).await {
            LeaseState::Held => {}
            // A compare-and-set said the row is not ours. Dropping it is right:
            // a newer claim owns it and will publish it.
            LeaseState::Lost => return RowOutcome::Fenced,
            // The renewal could not reach the database, so whether the claim
            // still holds is unknown. Rescheduling is the bounded answer: it
            // advances `attempt_count` and `available_at` under the generation
            // this worker still believes it has, and if that belief is wrong
            // the compare-and-set inside refuses it. Reporting `Fenced` here
            // would be a lie, and returning without a write would respin the
            // row every lease period for as long as the pool is down.
            LeaseState::Unknown => {
                return self.release_for_retry(&claimed, LEASE_RENEWAL_FAILED).await;
            }
        }

        let started = std::time::Instant::now();
        let answer = self
            .publisher
            .publish(&envelope, self.config.publish_deadline)
            .await;
        // Recorded for every attempt, accepted or not. CR-032 asks for publish
        // latency; measuring only the successes hides exactly the case an
        // operator needs the histogram for, which is a gateway that has become
        // slow enough to start timing out.
        let latency_ms = started.elapsed().as_secs_f64() * 1000.0;

        match answer {
            Ok(acceptance) => {
                metrics::record_publish_result(metrics::FAMILY_ACCEPTED, metrics::CLASS_ACCEPTED);
                metrics::record_publish_latency_ms(metrics::FAMILY_ACCEPTED, latency_ms);
                self.record_acceptance(&claimed, &acceptance).await
            }
            Err(failure) => {
                metrics::record_publish_result(failure.family_label(), failure.class_label());
                metrics::record_publish_latency_ms(failure.family_label(), latency_ms);
                match failure {
                    // Terminal is the only family that dead-letters. A refused
                    // credential is deliberately Transient in WP-111's
                    // classification, so it retains rows rather than losing
                    // them.
                    PublishFailure::Terminal(class) => {
                        if !self.terminal_is_final(class.as_metric_label(), &claimed) {
                            warn!(
                                event_id = %event_id,
                                class = class.as_metric_label(),
                                previous_class = ?claimed.last_error_class,
                                "Durable publish rejected this event; requeueing, because one \
                                 rejection is not a repeated one"
                            );
                            return self
                                .release_for_retry(&claimed, class.as_metric_label())
                                .await;
                        }
                        error!(
                            event_id = %event_id,
                            class = class.as_metric_label(),
                            attempt_count = claimed.attempt_count,
                            "Durable publish terminally rejected; dead-lettering"
                        );
                        self.dead_letter(event_id, claim_generation, class.as_metric_label())
                            .await
                    }
                    // NotAccepted may still have landed at the broker, so the
                    // row is retained pending with its ORIGINAL keys and
                    // republished. The gateway deduplicates on those keys.
                    PublishFailure::NotAccepted(reason) => {
                        warn!(
                            event_id = %event_id,
                            reason = reason.as_metric_label(),
                            "Durable publish answer did not prove acceptance; requeueing with the \
                             original keys"
                        );
                        self.release_for_retry(&claimed, reason.as_metric_label())
                            .await
                    }
                    PublishFailure::Transient(class) => {
                        debug!(
                            event_id = %event_id,
                            class = class.as_metric_label(),
                            "Durable publish failed transiently; backing off"
                        );
                        self.release_for_retry(&claimed, class.as_metric_label())
                            .await
                    }
                }
            }
        }
    }

    /// Whether a terminal-family failure may dead-letter this row now.
    ///
    /// CR-032 does **not** make every 4xx terminal on sight: "invalid scope,
    /// impossible identity mismatch, unsupported producer schema, or a
    /// **repeated** event-specific 4xx is terminal". The qualifier is
    /// load-bearing, because `client.rs` classifies a bare `INVALID_ARGUMENT`
    /// as [`TerminalClass::InvalidRequest`] — so without it one version-skewed
    /// or briefly misconfigured gateway drains a whole cell's backlog into dead
    /// letters at a batch per iteration, each row then needing a manual
    /// operator disposition to come back.
    ///
    /// Two groups, split by what the failure is a property *of*:
    ///
    /// * Properties of **this row**, final on the first attempt. `ScopeMismatch`
    ///   and `UnsupportedSchema` are named terminal outright by CR-032, and
    ///   `LocallyRejected` is this process's own bounds check refusing the
    ///   envelope before sending it. No retry changes any of the three.
    /// * Properties of the **answer**, final only when repeated.
    ///   `InvalidRequest` and [`ACCEPTANCE_OUT_OF_RANGE`] both describe what a
    ///   gateway said, not what the row is.
    ///
    /// "Repeated" is read as *consecutive*: the immediately preceding attempt
    /// on this row failed the same way. `last_error_class` carries that, and it
    /// is deliberately not `attempt_count`. That column counts every release —
    /// timeouts, 5xx, unproven answers — so a row that sat through a broker
    /// outage arrives at its first genuine rejection already looking like a
    /// repeat offender, which is precisely the mass-dead-letter case this
    /// check exists to prevent. `last_error_class` is overwritten on every
    /// release, so a transient failure between two rejections correctly breaks
    /// the run.
    ///
    /// TODO(WP-119 Step C): CR-032's *quarantine* disposition is a separate,
    /// stronger action with its own bar — twenty identical rejections over at
    /// least an hour, and only when gateway health proves other events of the
    /// same version publish. That belongs to Step C's operator command surface,
    /// which owns dispositions; it is not this loop's decision to make and is
    /// not a weaker form of the rule above.
    fn terminal_is_final(&self, class_label: &str, claimed: &ClaimedEvent) -> bool {
        let requires_repetition = class_label == TerminalClass::InvalidRequest.as_metric_label()
            || class_label == ACCEPTANCE_OUT_OF_RANGE;
        if !requires_repetition {
            return true;
        }
        claimed.last_error_class.as_deref() == Some(class_label)
    }

    /// Renew the lease when the publish deadline would otherwise race it.
    ///
    /// Three answers, not two. "This worker lost the claim" and "the database
    /// could not be reached to ask" call for opposite handling, and collapsing
    /// them into a boolean reported a pool outage as a fencing event: no write
    /// happened, no attempt was counted, and the row respun on every lease
    /// expiry for as long as the outage lasted.
    ///
    /// On a successful renewal the caller's `claim_expires_at` is advanced.
    /// Without that the threshold below stays tripped for the rest of the batch
    /// and every remaining row issues its own redundant renewal statement.
    async fn ensure_lease(&self, claimed: &mut ClaimedEvent) -> LeaseState {
        // The lease expiry is a *database* clock reading and the deadline is
        // measured on this process's clock, so this comparison carries whatever
        // skew exists between them. The `publish_deadline * 2` threshold, and
        // `config.rs`'s bound making that fit inside the lease, are the slack
        // that absorbs it.
        let remaining = claimed
            .claim_expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        if remaining >= self.config.publish_deadline * 2 {
            return LeaseState::Held;
        }

        // Sampled BEFORE the round trip, not after. The database stamps the
        // real expiry from its own `clock_timestamp()` at some point during
        // this call, and this process cannot read that back without a second
        // round trip. Taking `now` first makes the local value an
        // under-estimate by however long the call takes, which is the safe
        // direction: the worker believes the lease ends sooner than it does and
        // renews again early. Sampling after the call would over-estimate and
        // let it publish past a lease it no longer holds.
        let renewed_from = SystemTime::now();

        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                warn!(error = %e, "Could not check out a connection to renew an outbox claim");
                return LeaseState::Unknown;
            }
        };
        let outcome = relay::renew_claim(
            &**client,
            claimed.event.event_id,
            claimed.claim_generation,
            &self.config.owner,
            self.config.claim_lease,
        )
        .await;
        match outcome {
            Ok(CasOutcome::Applied) => {
                metrics::record_lease_renewal(metrics::CAS_APPLIED);
                claimed.claim_expires_at = renewed_from + self.config.claim_lease;
                LeaseState::Held
            }
            Ok(other) => {
                metrics::record_lease_renewal(cas_label(&other));
                metrics::record_cas_outcome(metrics::CAS_RENEW, cas_label(&other));
                warn!(
                    event_id = %claimed.event.event_id,
                    outcome = cas_label(&other),
                    "Lost the outbox claim before publishing; dropping the row"
                );
                LeaseState::Lost
            }
            Err(e) => {
                warn!(
                    event_id = %claimed.event.event_id,
                    error = %e,
                    "Outbox claim renewal could not reach the database; rescheduling the row"
                );
                LeaseState::Unknown
            }
        }
    }

    async fn record_acceptance(
        &self,
        claimed: &ClaimedEvent,
        acceptance: &BrokerAcceptance,
    ) -> RowOutcome {
        let event_id = claimed.event.event_id;
        let claim_generation = claimed.claim_generation;
        let record = match acceptance_record(acceptance) {
            Ok(record) => record,
            Err(detail) => {
                // The gateway answered with acceptance evidence the store
                // cannot hold. Leaving the row claimed would republish it on
                // every lease expiry forever without advancing `attempt_count`
                // — an unbounded duplicate stream at the broker that no backoff
                // slows and no counter records.
                //
                // It goes through the same repetition rule as a 4xx rather than
                // dead-lettering on sight, because every value that can
                // overflow here belongs to the stream or the gateway, not to
                // this event. One misbehaving gateway would otherwise
                // dead-letter the whole backlog, and each of those rows *was*
                // published, so every dead letter would also be a broker
                // duplicate.
                if !self.terminal_is_final(ACCEPTANCE_OUT_OF_RANGE, claimed) {
                    warn!(
                        event_id = %event_id,
                        detail,
                        "Broker acceptance evidence is out of range for the outbox row; \
                         requeueing. The broker may already hold this event"
                    );
                    return self
                        .release_for_retry(claimed, ACCEPTANCE_OUT_OF_RANGE)
                        .await;
                }
                error!(
                    event_id = %event_id,
                    detail,
                    "Broker acceptance evidence is out of range for the outbox row a second time; \
                     dead-lettering. The broker may already hold this event"
                );
                return self
                    .dead_letter(event_id, claim_generation, ACCEPTANCE_OUT_OF_RANGE)
                    .await;
            }
        };

        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                // The event is at the broker and the row is still pending. This
                // reschedules rather than dropping the claim, so the republish
                // is backed off and counted instead of repeating every lease
                // period at full speed. If the reschedule cannot reach the
                // database either, its own fallback leaves the lease to expire.
                error!(
                    event_id = %event_id,
                    error = %e,
                    "Could not record a broker acceptance: no connection. The row will be \
                     republished with its original keys after a backoff"
                );
                return self.release_for_retry(claimed, ACCEPT_WRITE_FAILED).await;
            }
        };

        match relay::record_broker_accepted(&**client, event_id, claim_generation, &record).await {
            Ok(CasOutcome::Applied) => {
                metrics::record_cas_outcome(metrics::CAS_ACCEPT, metrics::CAS_APPLIED);
                RowOutcome::Accepted
            }
            Ok(outcome @ CasOutcome::AlreadyAccepted) => {
                // Another attempt published the same logical event and recorded
                // it first. Not an error, and explicitly never retried: the
                // event is durable exactly once under its stable keys.
                metrics::record_cas_outcome(metrics::CAS_ACCEPT, cas_label(&outcome));
                debug!(event_id = %event_id, "Outbox row was already accepted by another attempt");
                RowOutcome::Duplicate
            }
            Ok(outcome @ (CasOutcome::StaleClaim { .. } | CasOutcome::Vanished)) => {
                metrics::record_cas_outcome(metrics::CAS_ACCEPT, cas_label(&outcome));
                warn!(
                    event_id = %event_id,
                    outcome = cas_label(&outcome),
                    "Fenced out while recording a broker acceptance; the publication stands and \
                     the newer claim owns the row"
                );
                RowOutcome::Fenced
            }
            Err(e) => {
                // CR-032's "acknowledged but the database update was lost" case.
                // The event is at the broker; the row is still pending. It is
                // rescheduled rather than left to its lease so the republish is
                // backed off and its attempt counted; the broker deduplicates
                // it on the stable keys either way.
                error!(
                    event_id = %event_id,
                    error = %e,
                    "Recording a broker acceptance failed after a successful publish; the row \
                     stays pending and will be republished with its original keys"
                );
                self.release_for_retry(claimed, ACCEPT_WRITE_FAILED).await
            }
        }
    }

    async fn release_for_retry(&self, claimed: &ClaimedEvent, error_class: &str) -> RowOutcome {
        let delay = self
            .config
            .backoff
            .next_delay(claimed.attempt_count, rand::random::<f64>());
        let next_attempt_at = SystemTime::now() + delay;

        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                warn!(
                    event_id = %claimed.event.event_id,
                    error = %e,
                    "Could not release an outbox claim for retry; the lease will expire and the \
                     row becomes claimable again"
                );
                metrics::record_deferred(metrics::DEFERRED_RETRY_POOL);
                return RowOutcome::Deferred;
            }
        };

        match relay::release_for_retry(
            &**client,
            claimed.event.event_id,
            claimed.claim_generation,
            error_class,
            next_attempt_at,
        )
        .await
        {
            Ok(CasOutcome::Applied) => {
                metrics::record_cas_outcome(metrics::CAS_RETRY, metrics::CAS_APPLIED);
                RowOutcome::Requeued
            }
            Ok(outcome) => {
                metrics::record_cas_outcome(metrics::CAS_RETRY, cas_label(&outcome));
                debug!(
                    event_id = %claimed.event.event_id,
                    outcome = cas_label(&outcome),
                    "Could not reschedule an outbox row: it is no longer this worker's to schedule"
                );
                RowOutcome::Fenced
            }
            Err(e) => {
                warn!(
                    event_id = %claimed.event.event_id,
                    error = %e,
                    "Rescheduling an outbox row failed; the lease will expire and the row becomes \
                     claimable again"
                );
                metrics::record_deferred(metrics::DEFERRED_RETRY_WRITE);
                RowOutcome::Deferred
            }
        }
    }

    /// Move a row to the dead-letter table.
    ///
    /// `terminal_class` is `&'static str` on purpose. It is both the persisted
    /// class and a metric label, and the only sources are closed sets —
    /// [`MapFailure::as_terminal_class`], [`TerminalClass::as_metric_label`],
    /// and this module's own two constants. Taking `&str` here would let an
    /// interpolated value through and would need a lookup table to widen it
    /// back for the label, which is a third hand-maintained copy of two
    /// vocabularies that drifts silently. The type does that job instead.
    async fn dead_letter(
        &self,
        event_id: uuid::Uuid,
        claim_generation: i64,
        terminal_class: &'static str,
    ) -> RowOutcome {
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                error!(
                    event_id = %event_id,
                    error = %e,
                    "Could not dead-letter a terminally failed outbox row; it will be reclaimed \
                     and fail the same way"
                );
                metrics::record_deferred(metrics::DEFERRED_DEAD_LETTER_POOL);
                return RowOutcome::Deferred;
            }
        };

        match relay::dead_letter(&mut client, event_id, claim_generation, terminal_class).await {
            Ok(CasOutcome::Applied) => {
                metrics::record_cas_outcome(metrics::CAS_DEAD_LETTER, metrics::CAS_APPLIED);
                metrics::record_dead_letter(terminal_class);
                RowOutcome::DeadLettered
            }
            Ok(outcome) => {
                metrics::record_cas_outcome(metrics::CAS_DEAD_LETTER, cas_label(&outcome));
                warn!(
                    event_id = %event_id,
                    outcome = cas_label(&outcome),
                    "Could not dead-letter an outbox row: it is no longer this worker's to move"
                );
                RowOutcome::Fenced
            }
            Err(e) => {
                error!(
                    event_id = %event_id,
                    error = %e,
                    "Dead-lettering an outbox row failed; it will be reclaimed and fail the same way"
                );
                metrics::record_deferred(metrics::DEFERRED_DEAD_LETTER_WRITE);
                RowOutcome::Deferred
            }
        }
    }

    /// Sleep, waking early on shutdown so drain is not delayed by a full idle
    /// interval.
    ///
    /// Returns whether the loop should stop. A dropped sender is treated as
    /// shutdown rather than ignored: `wait_for` returns `Err` immediately once
    /// every sender is gone, so an ignored error would make this return
    /// instantly on every call and spin the claim loop at full speed against
    /// Postgres. The server holds the sender for the process lifetime, so this
    /// is unreachable in production and entirely reachable from a test harness.
    async fn sleep_or_shutdown(
        &self,
        duration: Duration,
        shutdown: &mut watch::Receiver<bool>,
    ) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(duration) => false,
            // Both outcomes of this arm mean stop: `Ok` is the predicate
            // becoming true, `Err` is every sender gone.
            _ = shutdown.wait_for(|&stop| stop) => true,
        }
    }

    /// Everything the loop needs to know about its own configuration, for the
    /// server wiring's log line.
    pub fn config(&self) -> &EventRelayConfig {
        &self.config
    }
}

/// The bounded metric label for a compare-and-set outcome.
///
/// The `match` is exhaustive on purpose: a new `CasOutcome` variant becomes a
/// compile error here rather than a silently unlabelled increment.
pub const fn cas_label(outcome: &CasOutcome) -> &'static str {
    match outcome {
        CasOutcome::Applied => metrics::CAS_APPLIED,
        CasOutcome::StaleClaim { .. } => metrics::CAS_STALE_CLAIM,
        CasOutcome::AlreadyAccepted => metrics::CAS_ALREADY_ACCEPTED,
        CasOutcome::Vanished => metrics::CAS_VANISHED,
    }
}

/// Convert a gateway acceptance into the record the store persists.
///
/// The transport carries unsigned values and the columns are `bigint`, so an
/// out-of-range value is a real possibility rather than a theoretical one. It
/// is reported rather than clamped: a clamped broker sequence would be silently
/// wrong evidence in the checkpoint vector Step C compares against.
fn acceptance_record(acceptance: &BrokerAcceptance) -> Result<BrokerAcceptanceRecord, String> {
    let stream_epoch = i64::try_from(acceptance.stream_epoch)
        .map_err(|_| format!("stream_epoch {} exceeds i64", acceptance.stream_epoch))?;
    let broker_sequence = i64::try_from(acceptance.broker_sequence)
        .map_err(|_| format!("broker_sequence {} exceeds i64", acceptance.broker_sequence))?;
    let publisher_contract_version =
        i32::try_from(acceptance.publisher_contract_version).map_err(|_| {
            format!(
                "publisher_contract_version {} exceeds i32",
                acceptance.publisher_contract_version
            )
        })?;
    Ok(BrokerAcceptanceRecord {
        stream_identity: acceptance.stream_identity.clone(),
        stream_epoch,
        broker_sequence,
        gateway_response_id: acceptance.event_id.to_hyphenated(),
        publisher_contract_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_relay::envelope_map::MapFailure;
    use crate::plugins::remote_notification::EventId;

    fn acceptance() -> BrokerAcceptance {
        BrokerAcceptance {
            event_id: EventId::from_bytes([7u8; 16]),
            stream_identity: "durable".to_string(),
            stream_epoch: 1,
            broker_sequence: 42,
            publisher_contract_version: 1,
            broker_accepted_at: None,
        }
    }

    #[test]
    fn an_in_range_acceptance_becomes_a_store_record() {
        let record = acceptance_record(&acceptance()).expect("in range");
        assert_eq!(record.stream_identity, "durable");
        assert_eq!(record.stream_epoch, 1);
        assert_eq!(record.broker_sequence, 42);
        assert_eq!(record.publisher_contract_version, 1);
    }

    /// A clamp here would put silently wrong evidence into the checkpoint
    /// vector, so an out-of-range value must be refused instead.
    #[test]
    fn an_out_of_range_broker_sequence_is_refused_not_clamped() {
        let mut acceptance = acceptance();
        acceptance.broker_sequence = u64::MAX;
        assert!(acceptance_record(&acceptance).is_err());

        let mut acceptance = self::acceptance();
        acceptance.stream_epoch = u64::MAX;
        assert!(acceptance_record(&acceptance).is_err());

        let mut acceptance = self::acceptance();
        acceptance.publisher_contract_version = u32::MAX;
        assert!(acceptance_record(&acceptance).is_err());
    }

    #[test]
    fn every_cas_outcome_has_a_distinct_bounded_label() {
        let outcomes = [
            CasOutcome::Applied,
            CasOutcome::StaleClaim {
                current_claim_generation: 3,
            },
            CasOutcome::AlreadyAccepted,
            CasOutcome::Vanished,
        ];
        let mut labels: Vec<&'static str> = outcomes.iter().map(cas_label).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total);
    }

    /// Every class this module can persist — as a dead letter's
    /// `terminal_class` or as a row's `last_error_class` — must fit its column
    /// and stay a bounded metric label. The three module constants are easy to
    /// add without noticing they are also a metric dimension.
    #[test]
    fn every_persisted_class_is_a_bounded_column_safe_label() {
        let mut classes: Vec<&'static str> = vec![
            ACCEPTANCE_OUT_OF_RANGE,
            ACCEPT_WRITE_FAILED,
            LEASE_RENEWAL_FAILED,
        ];
        classes.extend(
            [
                MapFailure::RepositoryIdWidth(1),
                MapFailure::ZeroRepository,
                MapFailure::CellIdMismatch {
                    row: "a".into(),
                    configured: "b".into(),
                },
                MapFailure::NegativeRepositoryGeneration(-1),
                MapFailure::ZeroRepositoryGeneration,
                MapFailure::EventKindWidth,
                MapFailure::AggregateKindWidth,
                MapFailure::AggregateIdentityNotTransportable(0),
                MapFailure::AggregateVersionUndecodable("x".into()),
                MapFailure::AggregateVersionIdentityNotTransportable(0),
                MapFailure::NegativePayloadSchemaVersion(-1),
                MapFailure::PayloadOverCap(0),
            ]
            .iter()
            .map(MapFailure::as_terminal_class),
        );
        classes.extend(
            [
                TerminalClass::ScopeMismatch,
                TerminalClass::UnsupportedSchema,
                TerminalClass::InvalidRequest,
                TerminalClass::LocallyRejected,
            ]
            .into_iter()
            .map(TerminalClass::as_metric_label),
        );

        let total = classes.len();
        for class in &classes {
            assert!(!class.is_empty());
            assert!(class.is_ascii());
            assert!(!class.contains(' '));
            // `terminal_class` and `last_error_class` are both bounded at 64
            // bytes by their column CHECKs.
            assert!(class.len() <= 64, "`{class}` will not fit its column");
        }
        classes.sort_unstable();
        classes.dedup();
        assert_eq!(classes.len(), total, "persisted classes must be distinct");
    }

    /// The three classes that are properties of the row are terminal on sight.
    #[test]
    fn a_row_specific_terminal_class_is_final_on_the_first_attempt() {
        let worker = policy_worker();
        // A row that has already failed some OTHER way, so a test that passed
        // only because `last_error_class` happened to be `None` would not.
        let previously_failed = claimed_row(3, Some("timeout"));

        for class in [
            TerminalClass::ScopeMismatch,
            TerminalClass::UnsupportedSchema,
            TerminalClass::LocallyRejected,
        ] {
            assert!(
                worker.terminal_is_final(class.as_metric_label(), &previously_failed),
                "{} is a property of the row and is terminal on sight",
                class.as_metric_label()
            );
        }
    }

    /// The rule that keeps one misbehaving gateway from emptying a cell's
    /// backlog into dead letters. "Repeated" means the immediately preceding
    /// attempt failed the same way, so a transient failure in between breaks
    /// the run.
    #[test]
    fn an_answer_specific_class_is_final_only_after_the_same_class_twice_running() {
        let worker = policy_worker();

        for class in [
            TerminalClass::InvalidRequest.as_metric_label(),
            ACCEPTANCE_OUT_OF_RANGE,
        ] {
            assert!(
                !worker.terminal_is_final(class, &claimed_row(0, None)),
                "{class}: a first rejection must requeue"
            );
            assert!(
                worker.terminal_is_final(class, &claimed_row(1, Some(class))),
                "{class}: a second consecutive rejection is terminal"
            );
        }
    }

    /// `attempt_count` counts every release, including timeouts and 5xx, so a
    /// row that survived a broker outage arrives at its first genuine rejection
    /// with a large count. Keying on that count instead of the previous class
    /// is what would dead-letter the whole backlog the moment a gateway came
    /// partly back, and this is the assertion that catches it.
    #[test]
    fn a_long_run_of_transient_failures_does_not_make_the_first_rejection_terminal() {
        let worker = policy_worker();
        let after_an_outage = claimed_row(500, Some("broker_unavailable"));
        for class in [
            TerminalClass::InvalidRequest.as_metric_label(),
            ACCEPTANCE_OUT_OF_RANGE,
        ] {
            assert!(
                !worker.terminal_is_final(class, &after_an_outage),
                "{class}: 500 transient retries are not 500 rejections"
            );
        }
    }

    /// Two different answer-specific failures alternating are not a repetition
    /// of either.
    #[test]
    fn alternating_rejection_classes_never_reach_terminal() {
        let worker = policy_worker();
        assert!(!worker.terminal_is_final(
            TerminalClass::InvalidRequest.as_metric_label(),
            &claimed_row(9, Some(ACCEPTANCE_OUT_OF_RANGE))
        ));
        assert!(!worker.terminal_is_final(
            ACCEPTANCE_OUT_OF_RANGE,
            &claimed_row(9, Some(TerminalClass::InvalidRequest.as_metric_label()))
        ));
    }

    // -- fixtures for the policy tests ------------------------------------

    /// A worker with a pool and publisher that are never reached.
    ///
    /// `terminal_is_final` is pure over its two arguments, so it is decidable
    /// without a database. The pool is built lazily by `deadpool-postgres` and
    /// never connected here.
    fn policy_worker() -> EventRelayWorker {
        use crate::event_relay::config::EventRelayConfig;
        use crate::settings::OutboxRelaySettings;

        #[derive(Debug)]
        struct NeverPublishes;

        #[async_trait::async_trait]
        impl DurablePublisher for NeverPublishes {
            async fn publish(
                &self,
                _envelope: &crate::plugins::remote_notification::DurableEnvelopeV1,
                _deadline: Duration,
            ) -> Result<BrokerAcceptance, PublishFailure> {
                unreachable!("the terminal-classification policy never publishes")
            }
        }

        let pool = lore_postgres::pool::build_pool(
            "postgresql://unused@127.0.0.1:1/unused",
            1,
            &lore_postgres::pool::TlsConfig::default(),
        )
        .expect("a lazily-built pool needs no server");
        let config = EventRelayConfig::from_settings(&OutboxRelaySettings {
            enabled: true,
            ..OutboxRelaySettings::default()
        })
        .expect("the shipped defaults are in bounds");
        let readiness = Arc::new(EventRelayReadiness::new(
            config.max_oldest_unpublished,
            config.readiness_probe_interval,
            config.publish_deadline,
        ));
        EventRelayWorker::new(
            pool,
            Arc::new(NeverPublishes),
            config,
            readiness,
            EnvelopeSource {
                cell_id: "cell-a".to_string(),
                placement_epoch: 1,
                producer_instance_id: "loreserver-1".to_string(),
            },
        )
    }

    fn claimed_row(attempt_count: i32, last_error_class: Option<&str>) -> ClaimedEvent {
        use lore_postgres::domain::outbox::AggregateVersion;
        use lore_postgres::domain::outbox::OutboxEventRecord;

        ClaimedEvent {
            event: OutboxEventRecord {
                event_id: uuid::Uuid::from_bytes([5u8; 16]),
                cell_id: "cell-a".to_string(),
                idempotency_key: [1u8; 32],
                repository_id: vec![2u8; 16],
                repository_generation: 3,
                event_kind: "branch.pushed".to_string(),
                aggregate_kind: "branch".to_string(),
                aggregate_id: b"main".to_vec(),
                aggregate_version: AggregateVersion::ordinal_only(1).encode(),
                payload_schema_version: 1,
                payload: b"{}".to_vec(),
                created_at: SystemTime::now(),
            },
            claim_generation: 1,
            claim_expires_at: SystemTime::now() + Duration::from_secs(30),
            attempt_count,
            last_error_class: last_error_class.map(str::to_string),
        }
    }
}
