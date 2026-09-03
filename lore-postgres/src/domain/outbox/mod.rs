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
//!   epoch-reset requeue, lookup, backlog, admission, and the schema-state read
//!   Step B's startup gate refuses on.
//! * [`membership`] — Step C's receiver membership projection: one row per
//!   receiver generation, the per-cell counters every compare-and-set anchors
//!   on, and the ordered capture/baseline/readiness bootstrap.
//! * [`checkpoint`] — Step C's checkpoint vector, keyed by stream identity,
//!   stream epoch, receiver identity, and membership generation.
//! * [`evaluator`] — Step C's bounded `consumer_safe` evaluator. The only
//!   writer of that state, and it never infers it from a broker
//!   acknowledgement.
//! * [`prune`] — Step C's bounded retention pruning, which re-proves the
//!   checkpoint vector rather than trusting the state column.
//! * [`reset`] — Step C's durable stream-reset receipt: evidence, stored ack,
//!   fence, retirement.
//! * [`cutover`] — Step C's cutover marker, the key to Step B's fail-closed
//!   startup gate.
//!
//! **The relay worker loop is not here.** It is WP-119 Step B, in `lore-server`.
//! Nothing in this module publishes, waits, or decides a backoff. Neither is the
//! stream-reset gRPC service: [`reset`] owns the transaction, `lore-server`'s
//! `event_relay::reset_service` owns the authentication, the canonical
//! derivation, and the wire.

pub mod append;
/// WP-116's transaction-local event builders for the pinned CR-032 event set.
/// Producer-side only; nothing here appends, publishes, or decides anything.
pub mod builders;
pub mod checkpoint;
pub mod cutover;
pub mod evaluator;
pub mod membership;
pub mod prune;
pub mod relay;
pub mod reset;
pub mod schema;
pub mod version;

pub use append::AppendedEvent;
pub use append::OutboxEvent;
pub use append::append;
pub use append::idempotency_key;
pub use checkpoint::CheckpointOutcome;
pub use checkpoint::CheckpointRecord;
pub use checkpoint::CheckpointReport;
pub use checkpoint::PoisonEntry;
pub use checkpoint::SequenceGap;
pub use checkpoint::report_checkpoint;
pub use cutover::CutoverOutcome;
pub use cutover::stamp_cutover;
pub use evaluator::EvaluationBlock;
pub use evaluator::EvaluationOutcome;
pub use evaluator::SafeVector;
pub use evaluator::evaluate_consumer_safe;
pub use membership::CapturedPosition;
pub use membership::MembershipCas;
pub use membership::MembershipMember;
pub use membership::MembershipSnapshot;
pub use membership::MembershipState;
pub use membership::SafetyBlock;
pub use membership::read_membership_snapshot;
pub use prune::PruneOutcome;
pub use prune::prune_consumer_safe;
pub use prune::prune_dead_letters;
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
pub use relay::OutboxSchemaState;
pub use reset::AckInputs;
pub use reset::ResetAcceptance;
pub use reset::ResetReport;
pub use reset::StoredReset;
pub use reset::accept_reset;
pub use schema::OUTBOX_BASE_API_VERSION;
pub use schema::OUTBOX_RELAY_SCHEMA_VERSION;
pub use schema::OUTBOX_SCHEMA;
pub use schema::relay_is_compatible;
pub use version::AggregateVersion;
pub use version::VersionOrder;
