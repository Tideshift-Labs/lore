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
//! | [`evaluator_task`] | the bounded `consumer_safe` and retention loop |
//! | [`reset_wire`] | the frozen `StreamResetService` schema and derivation |
//! | [`reset_service`] | that service's authentication and receipt orchestration |
//! | [`readiness`] | the relay, event, and receiver facets, separate from storage readiness |
//! | [`admission`] | required-event mutation admission and its `RetryInfo` |
//! | [`startup`] | the fail-closed boot gate |
//! | [`retry_info`] | `google.rpc.RetryInfo`, hand-transcribed |
//! | [`wiring`] | server construction, in one reviewable sequence |
//!
//! # The admission seam is built here and read at the mutation choke point
//!
//! [`admission::OutboxAdmission`] answers from local Postgres facts only, and
//! [`admission::rejection_status`] maps a closed verdict to
//! `RESOURCE_EXHAUSTED` with bounded `RetryInfo`. WP-119 Phase 8 wired it:
//! [`wiring::spawn_event_relay`] attaches the handle to the
//! `DomainContext`, and `DomainContext::admit` — the single server-side choke
//! point every governed repository, branch, lock, and obliterate handler
//! reaches through `admit_at_entry` — refuses a closed verdict just before it
//! would return `Ok(Some(AdmittedOperation))`, so every client-fault
//! classification above still wins over a backlog rejection.
//!
//! `admit` stayed **synchronous**, and the twelve handler call sites were not
//! touched. The gate reads a cached verdict that the worker's readiness tick
//! refreshes; the database probe never runs on a mutation path. That is not
//! only an ergonomic win — `relay::admission_check` is bounded but still
//! `O(pending)`, so running it per mutation would cost the most exactly when
//! the cell is already behind.
//!
//! # `consumer_safe` is never inferred from an acknowledgement
//!
//! The relay worker advances a row to `broker_accepted` and stops there.
//! [`evaluator_task`] is the only thing in this process that advances
//! `consumer_safe`, and it does so only from the Postgres checkpoint vector
//! under one membership snapshot. CR-032 keeps the two facts separate precisely
//! so a relay cannot conflate them, and the split between these two modules is
//! that separation made structural.
//!
//! # What is still absent
//!
//! The operator command surface (status, inspection, replay, dead-letter
//! disposition) is Phase 8's, and a real pruning schedule beyond
//! [`evaluator_task`]'s own tick is too. WP-111 Phase 3 owns the durable
//! receiver itself: this package projects its membership and checkpoints, and
//! never consumes on its behalf.
//!
//! TODO(WP-119 Phase 8): the operator command surface and a pruning schedule.

pub mod admission;
pub mod config;
pub mod envelope_map;
pub mod evaluator_task;
pub mod metrics;
pub mod publisher;
pub mod readiness;
pub mod reset_service;
pub mod reset_wire;
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
pub use evaluator_task::ConsumerSafetyTask;
pub use publisher::DurablePublisher;
pub use readiness::EventRelayReadiness;
pub use readiness::ReadinessSnapshot;
pub use reset_service::StreamResetHandler;
pub use reset_wire::StreamResetServiceServer;
pub use startup::StartupRefusal;
pub use startup::enforce_startup_preconditions;
pub use worker::EventRelayWorker;
pub use worker::RowOutcome;
