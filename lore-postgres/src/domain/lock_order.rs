// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The shared row-lock order, expressed in code (CR-032 F-032-3 as amended).
//!
//! ```text
//! domain operation receipt -> repository -> branch -> lock namespace
//!   -> sorted fragment rows -> sorted associations -> outbox insert
//! ```
//!
//! Every domain transaction that takes more than one row lock takes them in
//! exactly this order. A transaction needing only a subset takes that subset in
//! the same relative order and skips the rest; it never reorders. The outbox
//! insert is always last, and the relay never takes domain row locks at all.
//!
//! **The receipt is position 0** because prepare/consume is the admission gate:
//! a mutation locks and consumes its `PREPARED` row before it touches any domain
//! state. That is both the natural place for it and the only position that
//! avoids a receipt-then-repository versus repository-then-receipt deadlock
//! cycle (F-032-3's 2026-08-28 amendment, raised as R-BLOCK-4).
//!
//! **The future-rejection quota row is deliberately not in this chain.** It is
//! locked only by future-rejection admission and by bounded quota prune/cleanup,
//! and those transactions write no receipt, authorization, claim, domain, or
//! outbox row by construction — so they never co-occur with the chain and form a
//! disjoint single-row lock. Should a future revision ever need a quota row and
//! a domain row in one transaction, the quota row takes position 0, ahead of the
//! receipt.
//!
//! The fragment-row and association segments sort by primary key ascending, so
//! two transactions touching an overlapping set acquire the overlap in the same
//! sequence. Nothing in WP-116 locks those segments — CR-031 owns them — but the
//! ordinal is reserved here so a later package cannot quietly insert itself
//! earlier in the chain.

use tokio_postgres::Transaction;

use crate::domain::errors::DomainError;

/// Position of one lockable row class in the shared order.
///
/// Represented as an explicit ordinal rather than left implicit in call order,
/// so [`LockSequence`] can *check* the order at runtime instead of trusting
/// every future caller to remember it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LockClass {
    /// The `PREPARED` admission row. Always first.
    OperationReceipt = 0,
    /// `lore_domain_repositories`.
    Repository = 1,
    /// `lore_domain_branches`.
    Branch = 2,
    /// The branch lock namespace. CR-030-owned; reserved here.
    LockNamespace = 3,
    /// Sorted fragment rows. CR-031-owned; reserved here.
    Fragments = 4,
    /// Sorted associations. CR-031-owned; reserved here.
    Associations = 5,
    /// The outbox append. Always last.
    OutboxInsert = 6,
}

/// Enforces the shared order within one transaction.
///
/// A deadlock from a reordered lock acquisition is one of the least pleasant
/// bugs to diagnose: it is load-dependent, it presents as a transient 40P01, and
/// bounded retry masks it into a latency problem rather than an error. Checking
/// the ordinal as locks are taken turns it into a deterministic, local failure
/// the first time a caller gets it wrong.
#[derive(Debug, Default)]
pub struct LockSequence {
    last: Option<LockClass>,
}

impl LockSequence {
    /// Start a fresh sequence for one transaction.
    pub fn new() -> Self {
        Self { last: None }
    }

    /// Record that `class` is about to be locked, rejecting an out-of-order or
    /// repeated-downward acquisition.
    ///
    /// Taking two rows of the *same* class is allowed — a transaction may lock
    /// several branch rows — because the within-class ordering is the primary
    /// key sort, not this ordinal.
    pub fn enter(&mut self, class: LockClass) -> Result<(), DomainError> {
        if let Some(last) = self.last
            && class < last
        {
            return Err(DomainError::Internal(format!(
                "lock order violation: tried to take {class:?} (position {}) after {last:?} \
                 (position {}); CR-032 F-032-3 fixes the order as receipt -> repository -> \
                 branch -> lock namespace -> fragments -> associations -> outbox",
                class as u8, last as u8
            )));
        }
        self.last = Some(class);
        Ok(())
    }

    /// The most recently entered class, for diagnostics.
    pub fn last(&self) -> Option<LockClass> {
        self.last
    }
}

/// Lock one repository row (position 1) and return its live/tombstone state.
///
/// Returns `None` when the identity has never existed. A tombstoned repository
/// still returns a row: identities are never reused, and the tombstone is the
/// fence that stops a delayed delete or push from targeting a later object with
/// the same ID.
pub async fn lock_repository(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    repository_id: &[u8],
) -> Result<Option<RepositoryLock>, DomainError> {
    sequence.enter(LockClass::Repository)?;
    let row = tx
        .query_opt(
            "SELECT state, generation, name, metadata_hash, default_branch_id \
             FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("repository row lock", e))?;
    Ok(row.map(|r| RepositoryLock {
        state: r.get("state"),
        generation: r.get("generation"),
        name: r.get("name"),
        metadata_hash: r.get("metadata_hash"),
        default_branch_id: r.get("default_branch_id"),
    }))
}

/// A locked repository row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryLock {
    /// `STATE_LIVE` or `STATE_TOMBSTONED`.
    pub state: i16,
    /// Monotonic; never wraps.
    pub generation: i64,
    /// Exact bytes; repository names do not fold case.
    pub name: String,
    /// Current metadata pointer.
    pub metadata_hash: Vec<u8>,
    /// Default branch identity.
    pub default_branch_id: Vec<u8>,
}

/// Lock one branch row (position 2).
///
/// A tombstoned branch still returns a row, preserving its last record for an
/// idempotent delete response. Push must never resurrect it, and re-creation
/// requires a new branch ID.
pub async fn lock_branch(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    repository_id: &[u8],
    branch_id: &[u8],
) -> Result<Option<BranchLock>, DomainError> {
    sequence.enter(LockClass::Branch)?;
    let row = tx
        .query_opt(
            "SELECT state, generation, repository_generation, name, metadata_hash, latest_hash \
             FROM lore_domain_branches \
             WHERE repository_id = $1 AND branch_id = $2 FOR UPDATE",
            &[&repository_id, &branch_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("branch row lock", e))?;
    Ok(row.map(|r| BranchLock {
        state: r.get("state"),
        generation: r.get("generation"),
        repository_generation: r.get("repository_generation"),
        name: r.get("name"),
        metadata_hash: r.get("metadata_hash"),
        latest_hash: r.get("latest_hash"),
    }))
}

/// A locked branch row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchLock {
    /// `STATE_LIVE` or `STATE_TOMBSTONED`.
    pub state: i16,
    /// Monotonic branch generation.
    pub generation: i64,
    /// Repository generation this branch was last written against.
    pub repository_generation: i64,
    /// Authored name.
    pub name: String,
    /// Current metadata pointer.
    pub metadata_hash: Vec<u8>,
    /// Current tip.
    pub latest_hash: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_order_is_accepted() {
        let mut s = LockSequence::new();
        for class in [
            LockClass::OperationReceipt,
            LockClass::Repository,
            LockClass::Branch,
            LockClass::LockNamespace,
            LockClass::Fragments,
            LockClass::Associations,
            LockClass::OutboxInsert,
        ] {
            s.enter(class).expect("canonical order must be accepted");
        }
    }

    #[test]
    fn a_subset_in_the_same_relative_order_is_accepted() {
        // The common shape: receipt, repository, outbox. Skipping the middle
        // classes is fine; reordering them is not.
        let mut s = LockSequence::new();
        s.enter(LockClass::OperationReceipt).expect("receipt");
        s.enter(LockClass::Repository).expect("repository");
        s.enter(LockClass::OutboxInsert).expect("outbox");
    }

    #[test]
    fn repository_before_receipt_is_the_deadlock_cycle_and_is_rejected() {
        // This exact inversion is what R-BLOCK-4 put the receipt at position 0
        // to prevent.
        let mut s = LockSequence::new();
        s.enter(LockClass::Repository).expect("repository");
        let err = s
            .enter(LockClass::OperationReceipt)
            .expect_err("receipt after repository must be rejected");
        assert!(matches!(err, DomainError::Internal(_)));
    }

    #[test]
    fn the_outbox_insert_cannot_be_followed_by_a_domain_lock() {
        let mut s = LockSequence::new();
        s.enter(LockClass::OutboxInsert).expect("outbox");
        assert!(s.enter(LockClass::Branch).is_err());
    }

    #[test]
    fn several_rows_of_one_class_are_allowed() {
        // A transaction may lock more than one branch; within a class the order
        // is the primary-key sort, not this ordinal.
        let mut s = LockSequence::new();
        s.enter(LockClass::Branch).expect("first branch");
        s.enter(LockClass::Branch).expect("second branch");
        assert_eq!(s.last(), Some(LockClass::Branch));
    }
}
