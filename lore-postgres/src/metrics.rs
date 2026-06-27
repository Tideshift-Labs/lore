// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Shared metrics for the CR-007 Postgres stores (C5 observability).
//!
//! Mirrors `lore-aws`'s instrumentation shape: one operation-latency histogram
//! per store, plus gauges for connection-pool saturation so cell operators can
//! see when the pool is the bottleneck (the AWS stores never expose this because
//! the SDK pools internally; deadpool does not, so we surface it). Tracing spans
//! on the public store methods (added with `#[tracing::instrument]`) carry per-op
//! timing + structured fields into the trace pipeline; these metrics feed the
//! OTLP metric pipeline.
//!
//! Latency is recorded via an RAII [`OpTimer`] taken at the top of each op, so it
//! is captured on every exit path — including `?` short-circuits — without
//! restructuring method bodies.

use std::time::Instant;

use deadpool_postgres::Status;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::METRICS_OPERATION_LATENCY_METRIC_NAME;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Gauge;
use opentelemetry::metrics::Histogram;

struct PostgresStoreInstrumentProvider;

impl InstrumentProvider for PostgresStoreInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.store.postgres"
    }
}

/// Per-store instruments. One per store instance (built in `connect`).
pub struct Instruments {
    /// Which store these belong to: `immutable` / `mutable` / `lock`. Stamped as
    /// a label so the three stores share one metric name but stay distinguishable.
    store: &'static str,
    latency_ms: Histogram<f64>,
    pool_waiting: Gauge<u64>,
    pool_available: Gauge<u64>,
}

impl Instruments {
    pub fn new(store: &'static str) -> Self {
        let provider = PostgresStoreInstrumentProvider;
        Self {
            store,
            latency_ms: provider.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            pool_waiting: provider.gauge("pool_waiting"),
            pool_available: provider.gauge("pool_available"),
        }
    }

    /// Sample pool saturation and start a latency timer for one operation. The
    /// returned guard records `{store, operation}` latency when dropped (every
    /// exit path), so callers just `let _t = …start(…)` at the top of the op.
    pub fn start(&self, operation: &'static str, status: Status) -> OpTimer<'_> {
        self.record_pool(status);
        OpTimer {
            instruments: self,
            operation,
            start: Instant::now(),
        }
    }

    /// Sample connection-pool saturation. `waiting > 0` means the pool is
    /// exhausted and callers are queued (the saturation signal operators watch).
    fn record_pool(&self, status: Status) {
        let labels = [KeyValue::new("store", self.store)];
        self.pool_waiting.record(status.waiting as u64, &labels);
        self.pool_available.record(status.available as u64, &labels);
    }
}

/// RAII latency timer; records op duration on drop.
pub struct OpTimer<'a> {
    instruments: &'a Instruments,
    operation: &'static str,
    start: Instant,
}

impl Drop for OpTimer<'_> {
    fn drop(&mut self) {
        let labels = [
            KeyValue::new("store", self.instruments.store),
            KeyValue::new("operation", self.operation),
        ];
        self.instruments
            .latency_ms
            .record(self.start.elapsed().as_secs_f64() * 1000.0, &labels);
    }
}
