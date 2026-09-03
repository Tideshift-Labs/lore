// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! OpenTelemetry instruments for the CR-032 relay worker.
//!
//! **Label discipline.** CR-032 and the notification-plane contract both
//! prohibit repository, event, actor, and producer identifiers as metric
//! labels. Every label below is a `&'static str` drawn from a closed set, so a
//! cardinality explosion would be a compile error rather than a runtime
//! surprise. Identifiers belong in the protected structured logs beside these
//! increments.
//!
//! The instruments are cached in a `OnceLock`, mirroring
//! `plugins::remote_notification::metrics`: the meter is built once against
//! whatever provider the global registry yields on first use, which is well
//! after telemetry init at boot.

use std::sync::OnceLock;

use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::Gauge;
use opentelemetry::metrics::Histogram;

struct EventRelayInstrumentProvider;

impl InstrumentProvider for EventRelayInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.outbox.relay"
    }
}

pub(crate) struct Instruments {
    /// Rows claimed, summed over batches.
    claimed_rows: Counter<u64>,
    /// Claim transactions that returned nothing.
    empty_claims: Counter<u64>,
    /// Leases renewed mid-batch.
    lease_renewals: Counter<u64>,
    /// Publication outcomes, by family and class.
    publish_results: Counter<u64>,
    /// Fenced compare-and-set outcomes, by operation and outcome.
    cas_outcomes: Counter<u64>,
    /// Rows moved to the dead-letter table, by terminal class.
    dead_letters: Counter<u64>,
    /// Round trip of one Publish attempt, accepted or not.
    publish_latency_ms: Histogram<f64>,
    /// Rows left to their lease because no database write could be made.
    deferred_rows: Counter<u64>,
    /// Oldest unpublished row age, in seconds, as last observed.
    backlog_oldest_age_seconds: Gauge<f64>,
    /// Unpublished row count, as last observed (a bounded probe).
    backlog_pending_rows: Gauge<u64>,
    /// Dead letters awaiting an operator disposition, as last observed.
    backlog_dead_letters: Gauge<u64>,
    /// Required-event mutation admissions refused, by the limit that tripped.
    admission_rejections: Counter<u64>,
}

impl Instruments {
    fn new() -> Self {
        let provider = EventRelayInstrumentProvider;
        let meter = provider.meter();
        Self {
            claimed_rows: meter
                .u64_counter(provider.scope_name("claims.rows"))
                .with_description("Outbox rows claimed by this relay worker")
                .build(),
            empty_claims: meter
                .u64_counter(provider.scope_name("claims.empty"))
                .with_description("Claim transactions that found no eligible row")
                .build(),
            lease_renewals: meter
                .u64_counter(provider.scope_name("claims.renewals"))
                .with_description("Claim leases renewed mid-batch, by outcome")
                .build(),
            publish_results: meter
                .u64_counter(provider.scope_name("publish.results"))
                .with_description("Durable Publish outcomes, by family and class")
                .build(),
            cas_outcomes: meter
                .u64_counter(provider.scope_name("cas.outcomes"))
                .with_description(
                    "Fenced compare-and-set outcomes against an outbox row, by operation \
                     and outcome",
                )
                .build(),
            dead_letters: meter
                .u64_counter(provider.scope_name("dead_letters"))
                .with_description("Outbox rows dead-lettered, by terminal class")
                .build(),
            publish_latency_ms: provider.latency_histogram_ms("publish.latency"),
            deferred_rows: meter
                .u64_counter(provider.scope_name("rows.deferred"))
                .with_description(
                    "Rows left to their claim lease because no database write could be made, \
                     by the site that gave up",
                )
                .build(),
            backlog_oldest_age_seconds: meter
                .f64_gauge(provider.scope_name("backlog.oldest_age_seconds"))
                .with_description("Age of the oldest unpublished outbox row, last observed")
                .build(),
            backlog_pending_rows: meter
                .u64_gauge(provider.scope_name("backlog.pending_rows"))
                .with_description("Unpublished outbox rows, last observed (bounded probe)")
                .build(),
            backlog_dead_letters: meter
                .u64_gauge(provider.scope_name("backlog.dead_letters"))
                .with_description("Dead letters awaiting an operator disposition, last observed")
                .build(),
            admission_rejections: meter
                .u64_counter(provider.scope_name("admission.rejections"))
                .with_description(
                    "Required-event mutations refused before their transaction, by limit",
                )
                .build(),
        }
    }

    pub(crate) fn instance() -> &'static Self {
        static INSTANCE: OnceLock<Instruments> = OnceLock::new();
        INSTANCE.get_or_init(Instruments::new)
    }
}

/// The bounded compare-and-set operation label set.
pub(crate) const CAS_ACCEPT: &str = "record_broker_accepted";
pub(crate) const CAS_RETRY: &str = "release_for_retry";
pub(crate) const CAS_DEAD_LETTER: &str = "dead_letter";
pub(crate) const CAS_RENEW: &str = "renew_claim";

/// The bounded compare-and-set outcome label set. These mirror
/// `lore_postgres::domain::outbox::CasOutcome`'s variants, and
/// `super::worker::cas_label` is the only place the two are related, so a new
/// variant is a compile error there rather than a silently unlabelled increment.
pub(crate) const CAS_APPLIED: &str = "applied";
pub(crate) const CAS_STALE_CLAIM: &str = "stale_claim";
pub(crate) const CAS_ALREADY_ACCEPTED: &str = "already_accepted";
pub(crate) const CAS_VANISHED: &str = "vanished";

/// The publish-outcome family label for a successful publish.
///
/// The three failure families come from `PublishFailure::family_label`, which
/// has no variant for success, so the fourth value is declared here and joins
/// the closed-set test below rather than being an inline literal at the call
/// site.
pub(crate) const FAMILY_ACCEPTED: &str = "accepted";
/// The class label within that family. Success has exactly one.
pub(crate) const CLASS_ACCEPTED: &str = "broker_accepted";

/// The bounded label set for a row left to its lease.
pub(crate) const DEFERRED_RETRY_POOL: &str = "retry_pool";
pub(crate) const DEFERRED_RETRY_WRITE: &str = "retry_write";
pub(crate) const DEFERRED_DEAD_LETTER_POOL: &str = "dead_letter_pool";
pub(crate) const DEFERRED_DEAD_LETTER_WRITE: &str = "dead_letter_write";

/// The bounded admission-limit label set.
pub(crate) const ADMISSION_AGE: &str = "oldest_pending_age";
pub(crate) const ADMISSION_ROWS: &str = "pending_rows";
pub(crate) const ADMISSION_BYTES: &str = "pending_bytes";

pub(crate) fn record_claimed_rows(rows: u64) {
    Instruments::instance().claimed_rows.add(rows, &[]);
}

pub(crate) fn record_empty_claim() {
    Instruments::instance().empty_claims.add(1, &[]);
}

pub(crate) fn record_lease_renewal(outcome: &'static str) {
    Instruments::instance()
        .lease_renewals
        .add(1, &[KeyValue::new("outcome", outcome)]);
}

pub(crate) fn record_publish_result(family: &'static str, class: &'static str) {
    Instruments::instance().publish_results.add(
        1,
        &[
            KeyValue::new("family", family),
            KeyValue::new("class", class),
        ],
    );
}

pub(crate) fn record_cas_outcome(operation: &'static str, outcome: &'static str) {
    Instruments::instance().cas_outcomes.add(
        1,
        &[
            KeyValue::new("operation", operation),
            KeyValue::new("outcome", outcome),
        ],
    );
}

pub(crate) fn record_dead_letter(terminal_class: &'static str) {
    Instruments::instance()
        .dead_letters
        .add(1, &[KeyValue::new("class", terminal_class)]);
}

pub(crate) fn record_publish_latency_ms(family: &'static str, millis: f64) {
    Instruments::instance()
        .publish_latency_ms
        .record(millis, &[KeyValue::new("family", family)]);
}

pub(crate) fn record_deferred(site: &'static str) {
    Instruments::instance()
        .deferred_rows
        .add(1, &[KeyValue::new("site", site)]);
}

pub(crate) fn record_backlog(oldest_age_seconds: f64, pending_rows: u64, dead_letters: u64) {
    let instruments = Instruments::instance();
    instruments
        .backlog_oldest_age_seconds
        .record(oldest_age_seconds, &[]);
    instruments.backlog_pending_rows.record(pending_rows, &[]);
    instruments.backlog_dead_letters.record(dead_letters, &[]);
}

pub(crate) fn record_admission_rejection(limit: &'static str) {
    Instruments::instance()
        .admission_rejections
        .add(1, &[KeyValue::new("limit", limit)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An OTel counter's recorded value cannot be read back here: the meter
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
    }

    /// The publish-outcome family label set spans four values, and only three
    /// of them come from `PublishFailure`. A success recorded under an inline
    /// literal would sit outside every check in this file.
    #[test]
    fn the_publish_family_labels_are_the_three_failure_families_plus_accepted() {
        use crate::plugins::remote_notification::NotAcceptedReason;
        use crate::plugins::remote_notification::PublishFailure;
        use crate::plugins::remote_notification::TerminalClass;
        use crate::plugins::remote_notification::TransientClass;

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
}
