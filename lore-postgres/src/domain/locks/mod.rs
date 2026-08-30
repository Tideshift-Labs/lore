// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-030 server-only lock ownership, leases, fencing, and push witnesses.
//!
//! The public lock proto and `LockStore` trait remain unchanged. This module is
//! the Postgres authority consumed by the current server slice and by the
//! later WP-108/WP-120 client contract. It reuses CR-029 receipts and CR-032's
//! lock order; it defines no receipt table, temporal constant, marker, quota,
//! or retry policy of its own.

mod coordinator;
pub mod schema;

pub use coordinator::AcquireOrRenewInput;
pub use coordinator::BackfillIssuerMap;
pub use coordinator::BackfillReport;
pub use coordinator::FencedLock;
pub use coordinator::ForceReleaseInput;
pub use coordinator::LockFencingReadiness;
pub use coordinator::LockMutationResult;
pub use coordinator::LockRejection;
pub use coordinator::LockResourceInput;
pub use coordinator::PostgresLockCoordinator;
pub use coordinator::PushLockWitness;
pub use coordinator::ReleaseInput;
pub use coordinator::VerifiedLockOwner;
pub use coordinator::lock_tenant_scope_key;
