// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032 transactional event outbox (WP-119-owned since `SCHEMA-119`).
//!
//! WP-116 landed the base under F-032-2: the `Outbox event` and `Outbox schema
//! state` rows and a bounded transaction-local append API, published as
//! `OUTBOX-BASE-API-READY`. `SCHEMA-119` transferred that base to WP-119, which
//! extends it **in place** rather than creating a parallel intent store.
//!
//! What is here now:
//!
//! * [`schema`] — both rows plus the relay claim, publication result, and dead
//!   letter of CR-032's persistent model, all on or beside the same event row.
//! * [`append`] — the producer side. Unchanged in shape, so WP-116/117/118
//!   producer call sites keep compiling; narrowed in what it accepts, because
//!   `aggregate_version` is now a checked encoding rather than opaque bytes.
//! * [`version`] — that encoding.
//! * [`relay`] — the relay-side store: claim, acknowledge, retry, dead letter,
//!   epoch-reset requeue, lookup, backlog, admission.
//!
//! **The relay worker loop is not here.** It is WP-119 Step B, in `lore-server`.
//! Nothing in this module publishes, waits, or decides a backoff. The receiver
//! membership/checkpoint projection, the `consumer_safe` evaluator, and
//! retention pruning are Step C and are likewise absent.

pub mod append;
pub mod relay;
pub mod schema;
pub mod version;

pub use append::AppendedEvent;
pub use append::OutboxEvent;
pub use append::append;
pub use append::idempotency_key;
pub use relay::AdmissionLimits;
pub use relay::AdmissionRejection;
pub use relay::AdmissionVerdict;
pub use relay::BrokerAcceptanceRecord;
pub use relay::CasOutcome;
pub use relay::ClaimedEvent;
pub use relay::DeadLetterOutcome;
pub use relay::OutboxBacklog;
pub use relay::OutboxEventRecord;
pub use relay::OutboxRow;
pub use schema::OUTBOX_BASE_API_VERSION;
pub use schema::OUTBOX_RELAY_SCHEMA_VERSION;
pub use schema::OUTBOX_SCHEMA;
pub use schema::relay_is_compatible;
pub use version::AggregateVersion;
pub use version::VersionOrder;
