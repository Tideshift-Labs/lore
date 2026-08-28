// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Mutex;

use lore_object_dispatch::DispatchMetricRecorder;
use lore_object_dispatch::DispatchMetrics;
use lore_object_dispatch::DispatchOperation;

#[derive(Default)]
struct RecordingMetrics {
    calls: Mutex<Vec<DispatchOperation>>,
}

impl DispatchMetricRecorder for RecordingMetrics {
    fn record_source_dark_rejection(&self, operation: DispatchOperation) {
        self.calls
            .lock()
            .expect("test metric recorder mutex must remain healthy")
            .push(operation);
    }
}

#[test]
fn all_covers_exactly_the_seven_closed_operations_with_distinct_labels() {
    assert_eq!(DispatchOperation::ALL.len(), 7);

    let labels: Vec<&str> = DispatchOperation::ALL
        .iter()
        .map(|operation| operation.metric_label())
        .collect();
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        7,
        "every operation must have a distinct label"
    );

    assert_eq!(
        labels,
        [
            "ReservePut",
            "UploadPut",
            "Submit",
            "GetRequest",
            "FetchResult",
            "AcknowledgeResult",
            "DiscardResult",
        ]
    );
}

#[test]
fn metric_label_is_closed_over_every_variant_by_exhaustive_match() {
    // A match without a wildcard arm fails to compile if `DispatchOperation` ever grows a variant
    // `metric_label()` doesn't handle -- this is a compile-time pin, not a runtime assertion.
    for operation in DispatchOperation::ALL {
        let label = match operation {
            DispatchOperation::ReservePut => "ReservePut",
            DispatchOperation::UploadPut => "UploadPut",
            DispatchOperation::Submit => "Submit",
            DispatchOperation::GetRequest => "GetRequest",
            DispatchOperation::FetchResult => "FetchResult",
            DispatchOperation::AcknowledgeResult => "AcknowledgeResult",
            DispatchOperation::DiscardResult => "DiscardResult",
        };
        assert_eq!(operation.metric_label(), label);
    }
}

#[test]
fn recorder_trait_only_ever_admits_the_closed_operation_enum() {
    // `DispatchMetricRecorder::record_source_dark_rejection` takes `DispatchOperation` by value,
    // not a `&str` or anything request-derived, so no caller-controlled string can become a label
    // through this seam -- provable at the call site, not by inspecting an exporter.
    let recorder = RecordingMetrics::default();
    for operation in DispatchOperation::ALL {
        recorder.record_source_dark_rejection(operation);
    }

    let calls = recorder
        .calls
        .lock()
        .expect("test metric recorder mutex must remain healthy");
    assert_eq!(*calls, DispatchOperation::ALL.to_vec());
}

#[test]
fn concrete_dispatch_metrics_implements_the_recorder_without_panicking() {
    // Smoke-test the real OTel-backed implementation: recording every closed operation through
    // `DispatchMetrics` must not panic even with no configured SDK meter provider (the OTel API
    // defaults to a no-op provider), proving the seam is safe to call unconditionally.
    let metrics = DispatchMetrics::default();
    for operation in DispatchOperation::ALL {
        metrics.record_source_dark_rejection(operation);
    }
    let via_new = DispatchMetrics::new();
    via_new.record_source_dark_rejection(DispatchOperation::ReservePut);
}
