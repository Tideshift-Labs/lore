// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's relay worker and its server wiring (WP-119 Step B).
//!
//! `lore-postgres`'s `domain::outbox` module is the durable half: it makes
//! claiming, acknowledging, rescheduling, and dead-lettering fenced
//! compare-and-set facts, and it deliberately cannot publish, sleep, or decide
//! a backoff. This module is the other half — the one loop per Postgres-mode
//! loreserver that turns those facts into gateway publications, plus the
//! readiness, admission, and startup enforcement that decide whether the loop
//! may run at all.
//!
//! | Module | Role |
//! | --- | --- |
//! | [`config`] | the validated `[outbox_relay]` shape and the retry schedule |
//! | [`publisher`] | the `DurablePublisher` seam over WP-111's gateway client |
//! | [`envelope_map`] | committed row to private `DURABLE_INVALIDATION` envelope |
//! | [`worker`] | the bounded claim/publish/settle loop |
//! | [`readiness`] | the relay and event facets, separate from storage readiness |
//! | [`admission`] | required-event mutation admission and its `RetryInfo` |
//! | [`startup`] | the fail-closed boot gate |
//! | [`retry_info`] | `google.rpc.RetryInfo`, hand-transcribed |
//! | [`wiring`] | server construction, in one reviewable sequence |
//!
//! # The admission seam is built here and called elsewhere
//!
//! [`admission::OutboxAdmission`] is complete: it answers from local Postgres
//! facts only, and [`admission::rejection_status`] maps a closed verdict to
//! `RESOURCE_EXHAUSTED` with bounded `RetryInfo`. It is not yet called.
//!
//! TODO(WP-119 Phase 8): call `OutboxAdmission::check` before the mutation
//! transaction opens, in `lore-server/src/domain.rs` at
//! `DomainContext::admit` — the single server-side choke point every governed
//! repository, branch, lock, and obliterate handler reaches through
//! `admit_at_entry`. The call belongs after carriage validation and before
//! `Ok(Some(AdmittedOperation))` is returned, so a malformed request still
//! gets `INVALID_ARGUMENT` rather than a backlog rejection, and it should run
//! only under enforcement. `admit` and `admit_at_entry` are synchronous today,
//! so wiring it makes them `async` and adds `.await` at the twelve handler
//! call sites. That file belongs to the concurrent producers lane in this
//! round, which is why the handle is built, tested, and handed over rather
//! than wired here.
//!
//! # What is deliberately absent
//!
//! The receiver membership and checkpoint projection, the `consumer_safe`
//! evaluator, the stream-reset service, retention pruning, and the operator
//! commands are WP-119 Step C. Nothing here advances `consumer_safe` or infers
//! consumer safety from a broker acknowledgement; CR-032 keeps those two facts
//! separate precisely so a relay cannot conflate them.
//!
//! TODO(WP-119 Step C): the checkpoint projection, the `consumer_safe`
//! evaluator, the reset service, pruning, and the operator command surface.

pub mod admission;
pub mod config;
pub mod envelope_map;
pub mod metrics;
pub mod publisher;
pub mod readiness;
pub mod retry_info;
pub mod startup;
pub mod wiring;
pub mod worker;

pub use admission::OutboxAdmission;
pub use config::EventRelayConfig;
pub use config::EventRelayConfigError;
pub use config::RelayBackoff;
pub use envelope_map::EnvelopeSource;
pub use envelope_map::MapFailure;
pub use envelope_map::map_event;
pub use publisher::DurablePublisher;
pub use readiness::EventRelayReadiness;
pub use readiness::ReadinessSnapshot;
pub use startup::StartupRefusal;
pub use startup::enforce_startup_preconditions;
pub use worker::EventRelayWorker;
pub use worker::RowOutcome;
