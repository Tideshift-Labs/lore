// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Closed-cardinality metrics for the in-process cell dispatch authority.
//!
//! Every label value comes from a closed enum defined here. Nothing request-derived — an identity,
//! a bucket, a key, a caller string — may become a label, because a label whose domain the caller
//! controls is an unbounded time-series axis. CR-033 D1 re-bases the closed enum on the authority's
//! operations rather than the generated gRPC handler set the removed service shell used.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

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

/// Count one wait for the drain hot-row lock that passed `lock_timeout`, labelled `procedure`
/// (the closed set of [`crate::drain_policy::drain_procedure_label`]). A steady rise means a
/// session holds the lock and does not let go; see
/// [`crate::drain_policy::DRAIN_HOT_ROW_LOCK_KEY`].
pub(crate) fn record_drain_hot_row_lock_wait_timeout(procedure: &'static str) {
    static TIMEOUTS: std::sync::OnceLock<Counter<u64>> = std::sync::OnceLock::new();
    HOT_ROW_LOCK_WAIT_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    TIMEOUTS
        .get_or_init(|| DispatchInstrumentProvider.counter("drain_hot_row_lock_wait_timeouts"))
        .add(1, &[KeyValue::new("procedure", procedure)]);
}

/// Count one hot-row session closed instead of pooled, labelled `reason` (the closed set of
/// [`crate::drain_policy::HotRowSessionClose::label`]). Each one is a new connection on the
/// next call.
pub(crate) fn record_drain_hot_row_session_closed(reason: crate::drain_policy::HotRowSessionClose) {
    static CLOSED: std::sync::OnceLock<Counter<u64>> = std::sync::OnceLock::new();
    if let Some(count) = HOT_ROW_SESSIONS_CLOSED.get(reason as usize) {
        count.fetch_add(1, Ordering::Relaxed);
    }
    CLOSED
        .get_or_init(|| DispatchInstrumentProvider.counter("drain_hot_row_sessions_closed"))
        .add(1, &[KeyValue::new("reason", reason.label())]);
}

/// Count one stuck-holder warning that named at least one holder. Local only: the warning itself
/// is the operator's signal.
pub(crate) fn record_drain_hot_row_holder_named() {
    HOT_ROW_HOLDER_WARNINGS.fetch_add(1, Ordering::Relaxed);
}

static HOT_ROW_LOCK_WAIT_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static HOT_ROW_HOLDER_WARNINGS: AtomicU64 = AtomicU64::new(0);
static HOT_ROW_SESSIONS_CLOSED: [AtomicU64; crate::drain_policy::HotRowSessionClose::ALL.len()] =
    [const { AtomicU64::new(0) }; crate::drain_policy::HotRowSessionClose::ALL.len()];

/// This process's totals of the two hot-row lock counters above, since it started. The `OTel`
/// counters carry the same counts; these exist so a test in the same process can read them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotRowLockCounts {
    pub lock_wait_timeouts: u64,
    /// Stuck-holder warnings that named a holder.
    pub holder_warnings: u64,
    /// Indexed like [`crate::drain_policy::HotRowSessionClose::ALL`].
    pub sessions_closed: [u64; crate::drain_policy::HotRowSessionClose::ALL.len()],
}

impl HotRowLockCounts {
    pub fn closed(&self, reason: crate::drain_policy::HotRowSessionClose) -> u64 {
        self.sessions_closed
            .get(reason as usize)
            .copied()
            .unwrap_or(0)
    }
}

pub fn hot_row_lock_counts() -> HotRowLockCounts {
    HotRowLockCounts {
        lock_wait_timeouts: HOT_ROW_LOCK_WAIT_TIMEOUTS.load(Ordering::Relaxed),
        holder_warnings: HOT_ROW_HOLDER_WARNINGS.load(Ordering::Relaxed),
        sessions_closed: std::array::from_fn(|index| {
            HOT_ROW_SESSIONS_CLOSED
                .get(index)
                .map_or(0, |count| count.load(Ordering::Relaxed))
        }),
    }
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
/// nothing: absence is not zero. Called at boot and when a CR-034 refresh adopts a newer head.
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
