// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-109 Phase 2 support: the shared-backend proof harness's own scaffolding.
//!
//! Split out of `tests/active_active_shared_backend.rs` so the cases read as
//! races rather than as setup. Nothing here asserts a production behaviour;
//! every module is either an environment gate, a namespace, a barrier, or a
//! tally.
//!
//! # The one rule every module here serves
//!
//! WP-109 Phase 2 requires deterministic barriers, not task scheduling, and
//! forbids a case whose environment is absent from counting as a pass. So:
//!
//! - [`env`] panics with a machine-readable marker rather than returning early,
//!   and the runner reports that marker as **NOT RUN**;
//! - [`barrier`] proves an interleaving happened by asking PostgreSQL, and
//!   **panics when it cannot** — a barrier that never engaged fails the case
//!   instead of letting it pass on a race it did not run;
//! - [`tally`] records winner/loser/unknown/duplicate counts and the seed every
//!   identity in the case was derived from.

pub mod barrier;
pub mod bucket;
pub mod domain_fixture;
pub mod env;
pub mod outbox_fixture;
pub mod sets;
pub mod tally;
