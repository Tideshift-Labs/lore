// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Moved from `src/store/composite.rs` (`report_replication_tests`) when the crate's lib test
//! harness was turned off.
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use lore_base::log::LoreLogLevel;
use lore_base::types::Address;
use lore_revision::store::composite::report_replication;
use lore_storage::StoreError;
use lore_telemetry::METRICS_SUCCESS_ATTRIBUTE_NAME;
use opentelemetry::Value;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_sdk::metrics::InMemoryMetricExporter;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::metrics::data::AggregatedMetrics;
use opentelemetry_sdk::metrics::data::MetricData;

/// A counter on a meter of its own, so the counts read back are this test's alone rather than
/// the process-wide provider's.
struct RecordedCounter {
    provider: SdkMeterProvider,
    exporter: InMemoryMetricExporter,
    counter: Counter<u64>,
}

impl RecordedCounter {
    fn new() -> Self {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_periodic_exporter(exporter.clone())
            .build();
        let counter = provider.meter("test").u64_counter("fanout").build();
        Self {
            provider,
            exporter,
            counter,
        }
    }

    fn count(&self, success: bool) -> u64 {
        self.provider.force_flush().expect("flush the test meter");
        let metrics = self.exporter.get_finished_metrics().expect("read metrics");
        let Some(last) = metrics.last() else {
            return 0;
        };
        last.scope_metrics()
            .flat_map(|scope| scope.metrics())
            .map(|metric| match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .filter(|point| {
                        point.attributes().any(|attribute| {
                            attribute.key.as_str() == METRICS_SUCCESS_ATTRIBUTE_NAME
                                && attribute.value == Value::Bool(success)
                        })
                    })
                    .map(|point| point.value())
                    .sum::<u64>(),
                data => panic!("expected a u64 sum, got {data:?}"),
            })
            .sum()
    }
}

fn report(
    failing: &AtomicBool,
    counter: &RecordedCounter,
    result: Result<(), StoreError>,
) -> Option<LoreLogLevel> {
    report_replication(
        "put",
        "replica",
        Address::default(),
        failing,
        &counter.counter,
        &result,
    )
}

fn failure() -> Result<(), StoreError> {
    Err(StoreError::internal("replica down"))
}

fn refusal() -> Result<(), StoreError> {
    Err(StoreError::from(lore_base::error::NotSupported {
        operation: "copy".to_string(),
    }))
}

#[test]
fn a_persistent_failure_warns_only_when_the_state_changes() {
    let failing = AtomicBool::new(false);
    let counter = RecordedCounter::new();

    assert_eq!(report(&failing, &counter, Ok(())), None);
    assert_eq!(
        report(&failing, &counter, failure()),
        Some(LoreLogLevel::Warn)
    );
    assert_eq!(
        report(&failing, &counter, failure()),
        Some(LoreLogLevel::Debug)
    );
    assert_eq!(
        report(&failing, &counter, failure()),
        Some(LoreLogLevel::Debug)
    );
    assert_eq!(report(&failing, &counter, Ok(())), Some(LoreLogLevel::Warn));
    assert_eq!(report(&failing, &counter, Ok(())), None);

    assert_eq!(counter.count(true), 3);
    assert_eq!(counter.count(false), 3);
}

#[test]
fn a_refusal_logs_at_debug_and_leaves_the_state_alone() {
    let failing = AtomicBool::new(false);
    let counter = RecordedCounter::new();

    assert_eq!(
        report(&failing, &counter, refusal()),
        Some(LoreLogLevel::Debug)
    );
    assert!(!failing.load(Ordering::Relaxed));
    assert_eq!(
        report(&failing, &counter, failure()),
        Some(LoreLogLevel::Warn)
    );
    assert_eq!(
        report(&failing, &counter, refusal()),
        Some(LoreLogLevel::Debug)
    );
    assert!(failing.load(Ordering::Relaxed));

    assert_eq!(counter.count(true), 0);
    assert_eq!(counter.count(false), 3);
}
