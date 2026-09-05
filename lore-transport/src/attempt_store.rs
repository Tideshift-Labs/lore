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

/// One dispatched-or-about-to-be-dispatched mutation.
///
/// Written before the request leaves the client and read back after a restart, so every field
/// has to be something the caller knows *without* a server answer. Nothing derived from a
/// response belongs here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRecord {
    /// The identity this attempt was dispatched under. The store's primary key.
    pub attempt_id: AttemptId,
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

    /// Read one attempt back.
    ///
    /// `None` means no such record, which after a restart means the attempt was never durably
    /// recorded and so was never dispatched.
    async fn lookup(&self, attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError>;

    /// Every attempt that has not been resolved, oldest first.
    ///
    /// The boot-recovery read. An empty result is the only state in which a client may consider
    /// itself to have no outstanding correctness work.
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError>;

    /// Durably associate an ownership token with the resource it locks.
    ///
    /// Separate from [`Self::record`] because the token arrives with the server's *response*,
    /// while the attempt record is written before the request. An acquire that returns a token
    /// the client then fails to store has produced a lock only an administrator can release.
    async fn record_ownership(
        &self,
        attempt: &AttemptId,
        ownership: &LockOwnership,
    ) -> Result<(), ProtocolError>;

    /// The token held for one resource, if this client holds one.
    async fn ownership_for(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError>;

    /// Mark an attempt resolved and release what it was holding.
    ///
    /// The only way a record leaves the store. There is no expiry and no eviction: an attempt
    /// nobody has resolved is precisely the one that must not be forgotten, and a store that
    /// aged records out would lose them in exactly the case they were written for.
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
#[cfg(any(test, feature = "test_seams"))]
pub struct VolatileAttemptStore {
    attempts: parking_lot::Mutex<Vec<AttemptRecord>>,
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
            attempts: parking_lot::Mutex::new(Vec::new()),
            ownership: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "test_seams"))]
#[async_trait]
impl AttemptStore for VolatileAttemptStore {
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        let mut attempts = self.attempts.lock();
        match attempts
            .iter_mut()
            .find(|stored| stored.attempt_id.as_uuid() == record.attempt_id.as_uuid())
        {
            Some(stored) => *stored = record.clone(),
            None => attempts.push(record.clone()),
        }
        Ok(())
    }

    async fn lookup(&self, attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        Ok(self
            .attempts
            .lock()
            .iter()
            .find(|stored| stored.attempt_id.as_uuid() == attempt.as_uuid())
            .cloned())
    }

    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        let mut attempts = self.attempts.lock().clone();
        attempts.sort_by_key(|record| record.recorded_at_unix_millis);
        Ok(attempts)
    }

    async fn record_ownership(
        &self,
        _attempt: &AttemptId,
        ownership: &LockOwnership,
    ) -> Result<(), ProtocolError> {
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
        _resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        self.attempts
            .lock()
            .retain(|stored| stored.attempt_id.as_uuid() != attempt.as_uuid());
        Ok(())
    }
}
