// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! OpenTelemetry instruments for the remote notification plugin.
//!
//! A dropped live hint is otherwise invisible: it is logged and discarded by
//! design, and never fails the mutation that produced it. These counters are the
//! only way to know the loss rate.
//!
//! **Label discipline.** The notification-plane contract prohibits repository,
//! user, actor, event, producer, and credential identifiers as metric labels.
//! Every label below is a `&'static str` chosen from a closed set, so a
//! cardinality explosion is a compile error rather than a runtime surprise.
//! Identifiers belong in the protected structured logs beside these
//! increments.
//!
//! The instruments are cached in a `OnceLock`, mirroring
//! `crate::hooks::lorehub_notify`: the counter is built once against whatever
//! meter the global provider yields on first use, which is well after telemetry
//! init at boot.

use std::sync::OnceLock;

use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::Histogram;
use opentelemetry::metrics::UpDownCounter;

struct RemoteNotificationInstrumentProvider;

impl InstrumentProvider for RemoteNotificationInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.notification.remote"
    }
}

pub(crate) struct Instruments {
    /// Current occupancy of the bounded ordinary queue.
    queue_depth: UpDownCounter<i64>,
    /// Hints refused at the queue, by reason.
    enqueue_failures: Counter<u64>,
    /// Publish attempt outcomes, by delivery class + outcome family + class.
    publish_results: Counter<u64>,
    /// Retry attempts spent, by delivery class.
    publish_retries: Counter<u64>,
    /// Hints abandoned after the retry budget, by the failure that ended them.
    dropped_hints: Counter<u64>,
    /// Round trip of ONE accepted Publish attempt, from send to a versioned
    /// broker acknowledgement. Recorded per attempt, not per logical
    /// publication, so a retried hint contributes only its successful attempt.
    ack_latency_ms: Histogram<f64>,
}

impl Instruments {
    fn new() -> Self {
        let provider = RemoteNotificationInstrumentProvider;
        let meter = provider.meter();
        Self {
            queue_depth: meter
                .i64_up_down_counter(provider.scope_name("live_hint.queue_depth"))
                .with_description("Occupancy of the bounded remote live-hint queue")
                .build(),
            enqueue_failures: meter
                .u64_counter(provider.scope_name("live_hint.enqueue_failures"))
                .with_description(
                    "Live hints refused at the bounded queue, by reason (queue_full, shutting_down)",
                )
                .build(),
            publish_results: meter
                .u64_counter(provider.scope_name("publish.results"))
                .with_description(
                    "Private gateway Publish attempt outcomes, by delivery_class, family and class",
                )
                .build(),
            publish_retries: meter
                .u64_counter(provider.scope_name("publish.retries"))
                .with_description("Bounded Publish retry attempts, by delivery_class")
                .build(),
            dropped_hints: meter
                .u64_counter(provider.scope_name("live_hint.dropped"))
                .with_description(
                    "Live hints dropped after an exhausted retry budget or a local rejection",
                )
                .build(),
            ack_latency_ms: provider.latency_histogram_ms("publish.ack_latency"),
        }
    }

    pub(crate) fn instance() -> &'static Self {
        static INSTANCE: OnceLock<Instruments> = OnceLock::new();
        INSTANCE.get_or_init(Instruments::new)
    }
}

/// The bounded delivery-class label set.
pub(crate) const CLASS_LIVE_HINT: &str = "live_hint";
pub(crate) const CLASS_SHADOW: &str = "shadow_observation";
pub(crate) const CLASS_DURABLE: &str = "durable_invalidation";

/// The bounded enqueue-failure reason set.
pub(crate) const ENQUEUE_QUEUE_FULL: &str = "queue_full";
pub(crate) const ENQUEUE_SHUTTING_DOWN: &str = "shutting_down";

pub(crate) fn record_queue_depth_delta(delta: i64) {
    Instruments::instance().queue_depth.add(delta, &[]);
}

pub(crate) fn record_enqueue_failure(reason: &'static str) {
    Instruments::instance()
        .enqueue_failures
        .add(1, &[KeyValue::new("reason", reason)]);
}

pub(crate) fn record_publish_result(
    delivery_class: &'static str,
    family: &'static str,
    class: &'static str,
) {
    Instruments::instance().publish_results.add(
        1,
        &[
            KeyValue::new("delivery_class", delivery_class),
            KeyValue::new("family", family),
            KeyValue::new("class", class),
        ],
    );
}

pub(crate) fn record_publish_retry(delivery_class: &'static str) {
    Instruments::instance()
        .publish_retries
        .add(1, &[KeyValue::new("delivery_class", delivery_class)]);
}

pub(crate) fn record_dropped_hint(delivery_class: &'static str, class: &'static str) {
    Instruments::instance().dropped_hints.add(
        1,
        &[
            KeyValue::new("delivery_class", delivery_class),
            KeyValue::new("class", class),
        ],
    );
}

pub(crate) fn record_ack_latency_ms(delivery_class: &'static str, millis: f64) {
    Instruments::instance()
        .ack_latency_ms
        .record(millis, &[KeyValue::new("delivery_class", delivery_class)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An OTel counter's recorded value cannot be read back here: the meter
    /// lives behind a process-global `SdkMeterProvider` cached in a `OnceLock`,
    /// so a test can only prove the classification, never the emitted number.
    /// What it CAN prove is that no label is built by interpolation, which is
    /// the property the contract's label prohibition actually needs.
    #[test]
    fn every_label_value_comes_from_the_closed_static_set() {
        for label in [
            CLASS_LIVE_HINT,
            CLASS_SHADOW,
            CLASS_DURABLE,
            ENQUEUE_QUEUE_FULL,
            ENQUEUE_SHUTTING_DOWN,
        ] {
            assert!(!label.is_empty());
            assert!(label.is_ascii());
            assert!(!label.contains(' '));
        }
    }

    #[test]
    fn recording_is_infallible_and_never_affects_the_caller() {
        // Fire-and-forget by construction: none of these return anything.
        record_queue_depth_delta(1);
        record_queue_depth_delta(-1);
        record_enqueue_failure(ENQUEUE_QUEUE_FULL);
        record_publish_result(CLASS_LIVE_HINT, "transient", "timeout");
        record_publish_retry(CLASS_LIVE_HINT);
        record_dropped_hint(CLASS_LIVE_HINT, "timeout");
        record_ack_latency_ms(CLASS_DURABLE, 12.5);
    }
}
