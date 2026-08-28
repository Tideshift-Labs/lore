// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Closed-cardinality metrics for the in-process cell dispatch authority.
//!
//! Every label value comes from a closed enum defined here. Nothing request-derived — an identity,
//! a bucket, a key, a caller string — may become a label, because a label whose domain the caller
//! controls is an unbounded time-series axis. CR-033 D1 re-bases the closed enum on the authority's
//! operations rather than the generated gRPC handler set the removed service shell used.

use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;

/// The closed set of operations the cell dispatch authority admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchOperation {
    ReservePut,
    UploadPut,
    Submit,
    GetRequest,
    FetchResult,
    AcknowledgeResult,
    DiscardResult,
}

impl DispatchOperation {
    pub const ALL: [Self; 7] = [
        Self::ReservePut,
        Self::UploadPut,
        Self::Submit,
        Self::GetRequest,
        Self::FetchResult,
        Self::AcknowledgeResult,
        Self::DiscardResult,
    ];

    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::ReservePut => "ReservePut",
            Self::UploadPut => "UploadPut",
            Self::Submit => "Submit",
            Self::GetRequest => "GetRequest",
            Self::FetchResult => "FetchResult",
            Self::AcknowledgeResult => "AcknowledgeResult",
            Self::DiscardResult => "DiscardResult",
        }
    }
}

pub trait DispatchMetricRecorder: Send + Sync + 'static {
    fn record_source_dark_rejection(&self, operation: DispatchOperation);
}

struct DispatchInstrumentProvider;

impl InstrumentProvider for DispatchInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "lore.object_dispatch"
    }
}

#[derive(Clone)]
pub struct DispatchMetrics {
    operation_rejections: Counter<u64>,
}

impl DispatchMetrics {
    pub fn new() -> Self {
        Self {
            operation_rejections: DispatchInstrumentProvider.counter("operation_rejections"),
        }
    }
}

impl Default for DispatchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatchMetricRecorder for DispatchMetrics {
    fn record_source_dark_rejection(&self, operation: DispatchOperation) {
        self.operation_rejections.add(
            1,
            &[
                KeyValue::new("operation", operation.metric_label()),
                KeyValue::new("outcome", "source_dark"),
            ],
        );
    }
}
