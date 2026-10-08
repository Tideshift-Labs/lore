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
use opentelemetry::metrics::Gauge;

use crate::budget_provenance::BudgetPinProvenance;
use crate::budget_provenance::classify_budget_pin;

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

/// Count one failed drain authority call, labelled `procedure` and `cause`. Both labels are closed
/// sets: [`crate::drain_policy::drain_procedure_label`] and
/// [`crate::drain_policy::DrainFailureCause::label`].
pub(crate) fn record_drain_authority_failure(procedure: &'static str, cause: &'static str) {
    static FAILURES: std::sync::OnceLock<Counter<u64>> = std::sync::OnceLock::new();
    FAILURES
        .get_or_init(|| DispatchInstrumentProvider.counter("drain_authority_failures"))
        .add(
            1,
            &[
                KeyValue::new("procedure", procedure),
                KeyValue::new("cause", cause),
            ],
        );
}

struct BudgetInstrumentProvider;

impl InstrumentProvider for BudgetInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.fragment.provider"
    }
}

/// Record the hard expiry, in unix seconds, that a documented-provider budget pin names. Label
/// free. The value is the expiry instant, not the time left, so a single record stays true until
/// the pin moves; the alert subtracts its own clock. A local pin carries no expiry and records
/// nothing: absence is not zero. Called at boot and when a CR-034 refresh adopts a successor.
/// The pin is the publisher's statement; the cell database still enforces the real expiry.
pub fn record_budget_pin_hard_expiry(pin: &crate::provider_client::BudgetPin) {
    static EXPIRY: std::sync::OnceLock<Gauge<i64>> = std::sync::OnceLock::new();
    if let Ok(BudgetPinProvenance::DocumentedProvider {
        hard_expires_at_unix_ms,
    }) = classify_budget_pin(pin)
    {
        EXPIRY
            .get_or_init(|| {
                let provider = BudgetInstrumentProvider;
                provider
                    .meter()
                    .i64_gauge(provider.scope_name("budget_hard_expiry_unix_seconds"))
                    .with_unit("seconds")
                    .with_description("Unix time at which the pinned object-store budget expires")
                    .build()
            })
            .record(hard_expires_at_unix_ms.div_euclid(1000), &[]);
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
