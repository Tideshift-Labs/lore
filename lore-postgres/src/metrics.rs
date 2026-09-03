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
use opentelemetry::metrics::Counter;
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

/// CR-032 relay instruments (WP-119 Step A).
///
/// Deliberately **unlabelled**. CR-032 prohibits repository, event, actor, and
/// producer IDs as metric labels, and the cheapest way to keep that true is to
/// give these instruments no label dimension at all rather than an empty one a
/// later edit could fill in. The store label the CR-007 stores carry is also
/// absent: there is exactly one outbox per cell.
///
/// The gauges are recorded from `relay::backlog`, whose counts are bounded
/// probes; a gauge sitting exactly at `relay::BACKLOG_PROBE_CEILING` means "at
/// least this many" rather than an exact total.
pub struct OutboxRelayInstruments {
    pending: Gauge<u64>,
    claimed: Gauge<u64>,
    dead_letters: Gauge<u64>,
    claims: Counter<u64>,
    accepts: Counter<u64>,
    retries: Counter<u64>,
}

impl OutboxRelayInstruments {
    /// Build the instrument set. One per relay worker.
    pub fn new() -> Self {
        let provider = PostgresStoreInstrumentProvider;
        Self {
            pending: provider.gauge("outbox_pending"),
            claimed: provider.gauge("outbox_claimed"),
            dead_letters: provider.gauge("outbox_dead_letters"),
            claims: provider.counter("outbox_claims"),
            accepts: provider.counter("outbox_accepts"),
            retries: provider.counter("outbox_retries"),
        }
    }

    /// Sample the three backlog gauges from one bounded read.
    pub fn record_backlog(&self, pending: u64, claimed: u64, dead_letters: u64) {
        self.pending.record(pending, &[]);
        self.claimed.record(claimed, &[]);
        self.dead_letters.record(dead_letters, &[]);
    }

    /// Rows a claim transaction actually leased.
    pub fn record_claimed(&self, rows: u64) {
        self.claims.add(rows, &[]);
    }

    /// One row advanced to `broker_accepted`.
    pub fn record_accepted(&self) {
        self.accepts.add(1, &[]);
    }

    /// One row released for a later attempt after a transient failure.
    pub fn record_retry(&self) {
        self.retries.add(1, &[]);
    }
}

impl Default for OutboxRelayInstruments {
    fn default() -> Self {
        Self::new()
    }
}
