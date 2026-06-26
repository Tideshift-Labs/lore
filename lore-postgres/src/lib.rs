// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Postgres-backed loreserver data-plane stores — the off-AWS metadata/lock
//! backend (CR-007).
//!
//! A single Postgres database per region cell backs all three of loreserver's
//! *coordination* stores — mutable (branch-tip CAS), immutable **metadata**
//! (fragment index), and lock — replacing DynamoDB. Immutable fragment **bytes**
//! continue to live in S3-compatible object storage (e.g. DO Spaces); only the
//! metadata/coordination moves to Postgres.
//!
//! The plugin **factories** that adapt these stores to loreserver's plugin
//! registry live on the server side in `lore-server/src/plugins/postgres.rs`
//! (mirroring how `lore-aws` store impls are wired by `plugins/aws.rs`).
//!
//! See `docs/lore-change-requests/cr-007-lore-postgres-backend.md` (Lorehub repo).
//! Store implementations are landed incrementally.

pub mod store;
