// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Closed-cardinality metrics for the source-dark service surface.

use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchRpc {
    ReservePut,
    UploadPut,
    Submit,
    GetRequest,
    FetchResult,
    AcknowledgeResult,
    DiscardResult,
}

impl DispatchRpc {
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
    fn record_source_dark_rejection(&self, rpc: DispatchRpc);
}

struct DispatchInstrumentProvider;

impl InstrumentProvider for DispatchInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "lore.object_dispatch"
    }
}

#[derive(Clone)]
pub struct DispatchMetrics {
    rpc_rejections: Counter<u64>,
}

impl DispatchMetrics {
    pub fn new() -> Self {
        Self {
            rpc_rejections: DispatchInstrumentProvider.counter("rpc_rejections"),
        }
    }
}

impl Default for DispatchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatchMetricRecorder for DispatchMetrics {
    fn record_source_dark_rejection(&self, rpc: DispatchRpc) {
        self.rpc_rejections.add(
            1,
            &[
                KeyValue::new("rpc.method", rpc.metric_label()),
                KeyValue::new("rpc.grpc.status_code", "Unavailable"),
                KeyValue::new("outcome", "source_dark"),
            ],
        );
    }
}
