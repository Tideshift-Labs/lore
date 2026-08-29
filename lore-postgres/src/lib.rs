// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Postgres-backed loreserver data-plane stores — the off-AWS coordination
//! backend (CR-007).
//!
//! A single Postgres database per region cell backs all three of loreserver's
//! *coordination* stores — mutable (branch-tip CAS), immutable lifecycle and
//! repository associations, and lock — replacing DynamoDB. Immutable fragment
//! bytes and authoritative representation metadata live on S3-compatible
//! objects (e.g. DO Spaces). Postgres also maintains an exact, rebuildable
//! metering projection over the associated hashes.
//!
//! The plugin **factories** that adapt these stores to loreserver's plugin
//! registry live on the server side in `lore-server/src/plugins/postgres.rs`
//! (mirroring how `lore-aws` store impls are wired by `plugins/aws.rs`).
//!
//! See `docs/lore-change-requests/cr-007-lore-postgres-backend.md` (Lorehub repo).
//! Store implementations are landed incrementally.

pub mod domain;
pub mod metrics;
pub mod pool;
pub mod store;
