// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 server-only domain transactions.
//!
//! The Postgres mutable store makes **one key** atomic at a time. Repository
//! create/delete, branch create/delete, and the final branch-push publication
//! are larger domain operations: a repository create today performs six
//! unsynchronised single-key writes interleaved with an auth-gRPC round trip and
//! two immutable-store serializations (worklog 254 §A.1). A sequence of
//! individually atomic `MutableStore` calls is not an atomic repository
//! operation, so a crash or a second loreserver can observe or leave a partial
//! one.
//!
//! This module makes the Postgres rows the lifecycle, generation, and tombstone
//! authority, with the existing `lore_mutable` rows kept as a compatibility
//! projection updated **in the same transaction**. The projection must never
//! lead the domain rows.
//!
//! # Scope and ownership
//!
//! `[SERVER]` only. No public protobuf field or method change, no C API change,
//! no `lore-client`/`lore-transport` dependency, no fragment/revision/metadata
//! format change. Operation identity reaches handlers as **gRPC request
//! metadata** (`lore-domain-operation-id-bin`,
//! `lore-domain-operation-fingerprint-bin`, `lore-domain-prepare-token-bin`),
//! following the fork's existing convention, so no `.proto` message changes.
//! One shared extractor validates them at handler entry; per-handler ad hoc
//! reads are forbidden, because the fork has been burned by body-versus-metadata
//! divergence before (CR-010).
//!
//! `domain/locks/` is **not** in this package — it belongs to the lock-fencing
//! package (CR-030). WP-116 owns only the transaction-local call site into it
//! from the final-push coordinator. `domain/outbox/` is the CR-032 base only,
//! and transfers to the relay package at `SCHEMA-119`.
//!
//! # What is here as of Phase 2
//!
//! Schema, migration/runtime parity, the bounded outbox append API, and the
//! restartable backfill with its cutover gate. The coordinator trait and the
//! transaction methods land in Phase 3.

pub mod backfill;
pub mod bypass;
pub mod coordinator;
pub mod errors;
pub mod lock_order;
pub mod maintenance;
pub mod outbox;
pub mod postgres_coordinator;
pub mod receipts;
pub mod retry;
pub mod schema;
pub mod schema_mediated;
pub mod store;

pub use errors::DomainError;
pub use errors::DomainOutcome;
pub use store::DatabaseIdentity;
pub use store::DomainSchemaState;
pub use store::PostgresDomainStore;
