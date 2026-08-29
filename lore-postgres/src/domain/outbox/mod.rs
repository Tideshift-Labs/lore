// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032 outbox **base** (WP-116-owned until `SCHEMA-119`).
//!
//! Scope is exactly F-032-2: the `Outbox event` and `Outbox schema state` rows,
//! a bounded transaction-local append API, and the conformance fixtures behind
//! `OUTBOX-BASE-API-READY`. There is no relay, no lease, no claim, no
//! publication result, no dead letter, and no receiver projection here — those
//! are WP-119's at `SCHEMA-119`, which takes exclusive ownership of this path
//! and extends it **in place** rather than creating a parallel intent store.
//!
//! WP-117 and WP-118 consume this exact base for their own transaction-local
//! producers and do not edit the schema, the API, or its fixtures.

pub mod append;
pub mod schema;

pub use append::AppendedEvent;
pub use append::OutboxEvent;
pub use append::append;
pub use append::idempotency_key;
pub use schema::OUTBOX_BASE_API_VERSION;
pub use schema::OUTBOX_SCHEMA;
