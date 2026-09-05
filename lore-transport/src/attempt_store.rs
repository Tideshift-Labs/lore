// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! The client's record of what it dispatched, before it dispatched it (WP-120, CR-029, CR-030).
//!
//! Two separate pieces of work need the same thing and neither has it today.
//!
//! CR-029's receipt lookup restates the exact identity of an attempt — operation id, method,
//! scope, fingerprint. [`crate::domain_receipt::DomainReceiptQuery`] says those are "recorded
//! before dispatch", and nothing in this client records them. CR-030's lock ownership token is
//! handed back on acquire and must be presented on release, and the Lore client keeps no local
//! lock state at all: release re-derives identity from path and branch, and `Query` returns an
//! empty token by contract. Both are the same missing thing, a durable per-attempt record on the
//! client, so this is one seam rather than two.
//!
//! **The store is not a cache.** A record exists so that an attempt whose answer was lost can be
//! reconciled later, which means it has to survive the process that wrote it. An implementation
//! that acknowledges a write before it is durable gives a caller permission to dispatch a
//! mutation it will not be able to ask about, and the caller cannot tell the difference. The one
//! in-tree implementation is deliberately test-only for that reason.
//!
//! What this module does not do: no implementation writes here for production. The desktop
//! implements it on WP-120's operation journal, and a `.lore/`-backed implementation for the CLI
//! is a separate lane, because a lock token at rest is a credential and needs review as one.
//! Neither the lock client's use of the token nor the reconcilers' use of the receipt identity
//! is in this file. This is the shape both agree on, and nothing more.

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;

use crate::domain_receipt::DomainReceiptQuery;
use crate::error::ProtocolError;
use crate::outcome::AttemptId;

/// Where an attempt stands.
///
/// Kept on the record rather than implied by the record's presence, because "gone" and "settled"
/// have to be distinguishable. A store that deleted a record on resolution would make a resolved
/// attempt read exactly like one that was never written, and a delayed transport callback or a
/// stale UI event arriving afterwards would find no record and could offer a retry for a mutation
/// that already applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptState {
    /// Recorded, and nothing authoritative has settled it.
    Unresolved,
    /// An operator acknowledged an attempt nobody can settle.
    ///
    /// Correctness is still unresolved: this appears in [`AttemptStore::unresolved`] exactly as
    /// [`Self::Unresolved`] does, keeps the repository's write latch, and carries the permanent
    /// no-old-id-replay marker that has to be restored before the client admits any new write.
    /// It is a distinct state only so a caller can restore that marker and show the audit trail.
    AdjudicatedUnknown,
    /// Authoritative evidence settled it. The record is retained as lineage.
    Resolved(AttemptResolution),
}

impl AttemptState {
    /// Whether this state still blocks new writes for the attempt's repository.
    ///
    /// `AdjudicatedUnknown` answers `true`, which is the whole reason it is not a resolution.
    pub fn is_unresolved(&self) -> bool {
        !matches!(self, Self::Resolved(_))
    }
}

/// One dispatched-or-about-to-be-dispatched mutation.
///
/// Written before the request leaves the client and read back after a restart, so every field
/// has to be something the caller knows *without* a server answer. Nothing derived from a
/// response belongs here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRecord {
    /// The identity this attempt was dispatched under. The store's primary key.
    pub attempt_id: AttemptId,
    /// Where the attempt stands. A fresh record is [`AttemptState::Unresolved`].
    pub state: AttemptState,
    /// The RPC, named as [`crate::outcome::GrpcRpc::wire_name`] names it, so a stored record can
    /// be read against the service definition without a translation table.
    pub operation: String,
    /// The repository the mutation targets.
    pub repository: RepositoryId,
    /// When the record was written, client clock, milliseconds since the Unix epoch. Used to
    /// order an operator's view of unresolved work, never to expire a record.
    pub recorded_at_unix_millis: i64,
    /// The CR-029 receipt identity, for the families that have one.
    ///
    /// `None` is not "not yet known" — it means this operation family has no authoritative
    /// receipt to look up, so no later read can resolve it. A caller that stores `None` is
    /// recording that fact deliberately.
    pub receipt: Option<DomainReceiptQuery>,
}

/// A CR-030 lock ownership token, held against the resource it was issued for.
///
/// Keyed by branch and resource rather than by attempt, because release happens in a different
/// process lifetime than acquire and the releasing caller knows what it is unlocking, not which
/// attempt once locked it.
///
/// The token is a credential. An implementation that persists one is storing a secret at rest and
/// owes the same care as any other credential store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockOwnership {
    /// The attempt that acquired this lock.
    ///
    /// Carried on the ownership rather than only on the acquiring call, because releasing the
    /// lock needs it: a release whose answer is lost is reconciled through the receipt for the
    /// *acquiring* attempt, and the releasing caller looks the ownership up by resource. Without
    /// this field the lookup returns a token and loses the identity the receipt is filed under.
    pub attempt_id: AttemptId,
    /// The branch the lock is scoped to.
    pub branch: Context,
    /// The locked resource.
    pub resource_hash: Hash,
    /// The opaque ownership token the server issued. Never logged.
    pub token: Bytes,
}

/// How an attempt stopped being unresolved.
///
/// Only three, and deliberately not five. `StillUnknown` is the absence of a resolution: the
/// record stays exactly as it is and the caller asks again later. `AdjudicatedUnknown` is an
/// operator acknowledging an attempt nobody can settle, which changes what the UI shows and
/// changes nothing about whether the attempt was applied — so it is not a resolution either, and
/// a store that accepted it here would be inviting a caller to drop the record on the strength
/// of a human clicking through a dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptResolution {
    /// Authoritative evidence proved the mutation happened.
    Applied,
    /// Authoritative evidence proved it did not.
    NotApplied,
    /// Authoritative evidence attributed a linearized conflict to this exact attempt.
    Conflicted,
}

/// The client's durable record of its own attempts.
///
/// Every method is fallible because every implementation of consequence touches a disk. A caller
/// that cannot record an attempt must not dispatch it: dispatching first and recording second is
/// the ordering that produces exactly the unreconcilable mutation this exists to prevent.
#[async_trait]
pub trait AttemptStore: Send + Sync {
    /// Durably record an attempt. Returns only once the record would survive a crash.
    ///
    /// Called before dispatch, never after. Recording the same attempt id twice is the caller
    /// retrying its own write and must be accepted, overwriting the previous record rather than
    /// failing or duplicating.
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError>;

    /// Read one attempt back, whatever state it is in.
    ///
    /// `None` means no such record ever existed, which after a restart means the attempt was
    /// never durably recorded and so was never dispatched. A resolved attempt is *not* `None`:
    /// it comes back carrying [`AttemptState::Resolved`]. That distinction is the point — a late
    /// transport callback or a stale UI event that finds `None` may offer a fresh attempt, and it
    /// must never be able to do that for a mutation that already applied.
    async fn lookup(&self, attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError>;

    /// Every attempt still blocking writes, oldest first.
    ///
    /// The boot-recovery read, and the only state in which a client may consider itself to have
    /// no outstanding correctness work is an empty result. Includes
    /// [`AttemptState::AdjudicatedUnknown`] records, whose no-old-id-replay marker and write latch
    /// have to be restored before any new write is admitted.
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError>;

    /// Durably associate an ownership token with the resource it locks.
    ///
    /// Separate from [`Self::record`] because the token arrives with the server's *response*,
    /// while the attempt record is written before the request. An acquire that returns a token
    /// the client then fails to store has produced a lock only an administrator can release.
    async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError>;

    /// The token held for one resource, if this client holds one.
    async fn ownership_for(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError>;

    /// Settle an attempt and release any lock ownership it held.
    ///
    /// Moves the record to [`AttemptState::Resolved`] and *keeps* it. Nothing removes a record:
    /// there is no expiry, no eviction, and no delete. An unresolved attempt is precisely the one
    /// that must not be forgotten, and a resolved one is the lineage that stops a late callback
    /// or a restored snapshot from offering a retry for a mutation that already happened.
    ///
    /// Compaction of long-settled lineage is an implementation's own business, and any
    /// implementation that does it owes the same argument this trait makes: that nothing which
    /// could still resurrect a retry affordance is what got compacted.
    async fn resolve(
        &self,
        attempt: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError>;
}

/// An in-memory [`AttemptStore`], for tests only.
///
/// It satisfies the trait's *shape* and violates its central promise: nothing here survives the
/// process. It is behind `test_seams` for the reason the feature exists — production must not be
/// able to reach it by accident, because a durable-intent store that silently forgets is worse
/// than none at all. A caller with no real store should fail to start, not quietly get this one.
/// One more thing to know before reaching for it: a workspace-wide `--all-targets` build unifies
/// this crate's features, so `test_seams` is on for `lore` and `loreserver` in that build and
/// this type is nameable there. The gate keeps it out of a release artifact, not out of every
/// compilation, so it is a guard against reaching for it by accident rather than a wall.
#[cfg(any(test, feature = "test_seams"))]
pub struct VolatileAttemptStore {
    attempts: parking_lot::Mutex<std::collections::HashMap<uuid::Uuid, AttemptRecord>>,
    ownership: parking_lot::Mutex<Vec<LockOwnership>>,
}

#[cfg(any(test, feature = "test_seams"))]
impl Default for VolatileAttemptStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test_seams"))]
impl VolatileAttemptStore {
    pub fn new() -> Self {
        Self {
            attempts: parking_lot::Mutex::new(std::collections::HashMap::new()),
            ownership: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "test_seams"))]
#[async_trait]
impl AttemptStore for VolatileAttemptStore {
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        self.attempts
            .lock()
            .insert(record.attempt_id.as_uuid(), record.clone());
        Ok(())
    }

    async fn lookup(&self, attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        Ok(self.attempts.lock().get(&attempt.as_uuid()).cloned())
    }

    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        let mut attempts: Vec<AttemptRecord> = self
            .attempts
            .lock()
            .values()
            .filter(|record| record.state.is_unresolved())
            .cloned()
            .collect();
        // Tie-broken by the attempt id, which is a v7 and so itself mint-ordered. A client clock
        // can repeat a millisecond or step backwards, and an order that changed between two reads
        // of the same unchanged store would be a poor thing to show an operator.
        attempts.sort_by(|left, right| {
            left.recorded_at_unix_millis
                .cmp(&right.recorded_at_unix_millis)
                .then_with(|| left.attempt_id.as_uuid().cmp(&right.attempt_id.as_uuid()))
        });
        Ok(attempts)
    }

    async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
        let mut held = self.ownership.lock();
        match held
            .iter_mut()
            .find(|s| s.branch == ownership.branch && s.resource_hash == ownership.resource_hash)
        {
            Some(stored) => *stored = ownership.clone(),
            None => held.push(ownership.clone()),
        }
        Ok(())
    }

    async fn ownership_for(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        Ok(self
            .ownership
            .lock()
            .iter()
            .find(|s| s.branch == *branch && s.resource_hash == *resource_hash)
            .cloned())
    }

    async fn resolve(
        &self,
        attempt: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        if let Some(stored) = self.attempts.lock().get_mut(&attempt.as_uuid()) {
            stored.state = AttemptState::Resolved(resolution);
        }
        self.ownership
            .lock()
            .retain(|held| held.attempt_id.as_uuid() != attempt.as_uuid());
        Ok(())
    }
}
