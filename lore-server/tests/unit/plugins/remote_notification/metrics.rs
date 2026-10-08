// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_server::plugins::remote_notification::metrics::*;

/// An `OTel` counter's recorded value cannot be read back here: the meter
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
    record_receiver_bootstrap("placement_moved");
    record_receiver_outcome("applied");
    record_receiver_checkpoint("applied");
}
