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
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;

use crate::domain_receipt::DomainReceiptQuery;
use crate::error::ProtocolError;
use crate::outcome::AttemptId;

/// A CR-030 ownership token: the bearer secret a fenced cell issues on acquire.
///
/// A newtype rather than a bare `Bytes` for one reason that is not tidiness. Possession of these
/// 32 bytes is the whole authority to release the lock they were issued for, so a derived `Debug`
/// on any struct holding one would print a live credential into whatever formatted it. The
/// [`std::fmt::Debug`] here redacts, and every type in this crate that carries a token holds it
/// through this newtype so that redaction cannot be forgotten at a new call site.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipToken(Bytes);

impl OwnershipToken {
    /// The exact width CR-030 mints and the server's request normalisation admits.
    pub const LEN: usize = 32;

    /// Read a token off the wire, or off a durable record written from the wire.
    ///
    /// Three answers, and the third is the point:
    ///
    /// * empty is `Ok(None)` — a cell that is not routing through the fenced authority returns
    ///   an empty token on every acquire, and that is not an error;
    /// * exactly [`Self::LEN`] is `Ok(Some)`;
    /// * any other width is an error rather than a silently dropped token. A token this client
    ///   cannot hold is a lock this client cannot release, and answering `None` there would hide
    ///   that behind an ordinary-looking acquire.
    pub fn from_wire(bytes: &[u8]) -> Result<Option<Self>, ProtocolError> {
        match bytes.len() {
            0 => Ok(None),
            Self::LEN => Ok(Some(Self(Bytes::copy_from_slice(bytes)))),
            other => Err(ProtocolError::internal(format!(
                "lock ownership token must be {} bytes, got {other}",
                Self::LEN
            ))),
        }
    }

    /// The raw token, for the one place that has to put it on the wire or in the store.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}

impl std::fmt::Debug for OwnershipToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnershipToken(<redacted>)")
    }
}

/// One resource of a lock request, carrying whatever ownership this client holds for it.
///
/// `None` is deliberately not an error on the request path. An unfenced cell issues no token, so
/// the token this client holds for a lock it acquired there is legitimately absent, and a client
/// that refused to send a tokenless resource could release nothing on such a cell. The server
/// decides whether a token was required; this type only reports what the client has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FencedLockResource {
    /// The resource being locked, renewed, or released.
    pub resource: LockResource,
    /// The token issued for this exact resource, if this client holds one.
    pub expected_ownership_token: Option<OwnershipToken>,
}

impl FencedLockResource {
    /// A resource this client holds no ownership for: a first acquire, or any resource on a cell
    /// that issues no tokens.
    pub fn tokenless(resource: LockResource) -> Self {
        Self {
            resource,
            expected_ownership_token: None,
        }
    }

    /// A resource carrying the ownership this client holds for it, if any.
    pub fn with_token(resource: LockResource, token: Option<OwnershipToken>) -> Self {
        Self {
            resource,
            expected_ownership_token: token,
        }
    }
}

/// One lock the server just granted, with the token it minted for it.
///
/// Separate from [`LockData`] rather than a field on it, because `LockData` is also what the read
/// paths return and what the server's own stores project. A token field there would be empty on
/// every read and would invite a caller to look for one where the contract guarantees none.
#[derive(Clone, Debug, PartialEq)]
pub struct AcquiredLock {
    /// The lock as the read paths would also describe it.
    pub lock: LockData,
    /// The ownership token, present only from `Lock` and `AdminLock` on a fenced cell.
    pub ownership_token: Option<OwnershipToken>,
}

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
#[derive(Clone, PartialEq, Eq)]
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
    pub token: OwnershipToken,
}

/// Written out rather than derived so that the token's own redaction cannot be bypassed by
/// formatting the struct that holds it.
impl std::fmt::Debug for LockOwnership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockOwnership")
            .field("attempt_id", &self.attempt_id)
            .field("branch", &self.branch)
            .field("resource_hash", &self.resource_hash)
            .field("token", &self.token)
            .finish()
    }
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
///
/// # Two jobs, and an embedder is only given one of them
///
/// This trait carries attempt records *and* lock ownership tokens, and for locks those two jobs
/// belong to two different stores. A store an embedder supplies through an entry point such as
/// `lore::lock::file_acquire_with_attempt_store` is used for attempt records only:
/// [`record`](AttemptStore::record), [`lookup`](AttemptStore::lookup),
/// [`unresolved`](AttemptStore::unresolved) and [`resolve`](AttemptStore::resolve). Lore never
/// calls [`record_ownership`](AttemptStore::record_ownership),
/// [`ownership_for`](AttemptStore::ownership_for) or
/// [`clear_ownership`](AttemptStore::clear_ownership) on it, so an embedder that implements those
/// three as `unimplemented!()` would never find out, and one that implements them faithfully will
/// see them stay empty.
///
/// The reason is that the two jobs have opposite requirements. An attempt record must live in the
/// caller's own journal, or the caller cannot reconcile what it dispatched. An ownership token must
/// live in the repository's `.lore/` store, because a direct call and a call delegated under
/// `LORE_USE_SERVICE` both derive that same store from the same repository path, and a token
/// written by one has to be readable by the other. Put ownership in an embedder's store and a
/// delegated acquire writes its token somewhere the later release will not look, which strands a
/// lock that only an administrator can then clear.
///
/// So lore derives its own ownership store from the repository regardless of what the embedder
/// supplies, and the embedder's store holds records. A single implementation still serves the CLI,
/// which uses one store for both jobs because it has no second party to disagree with.
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

    /// The tokens held for a batch of resources, one answer per request, in order.
    ///
    /// Defaulted to a loop over [`Self::ownership_for`], so an implementation with no cheaper
    /// bulk read needs nothing here. An implementation whose single read touches a disk should
    /// override it: `lore lock release --force` rebuilds its set from a `Query` over the whole
    /// branch, and asking one resource at a time turns one read into thousands.
    async fn ownership_for_batch(
        &self,
        resources: &[(Context, Hash)],
    ) -> Result<Vec<Option<LockOwnership>>, ProtocolError> {
        let mut held = Vec::with_capacity(resources.len());
        for (branch, resource_hash) in resources {
            held.push(self.ownership_for(branch, resource_hash).await?);
        }
        Ok(held)
    }

    /// Forget the token for one resource, once the server has confirmed the lock is gone.
    ///
    /// The release path's counterpart to [`Self::record_ownership`], and separate from
    /// [`Self::resolve`] because the two answer different questions. `resolve` settles the
    /// attempt that *acquired* a lock and drops what that attempt was holding; this is called by
    /// whoever later releases the lock, which is usually a different attempt in a different
    /// process lifetime, and which is the only party that knows the release succeeded.
    ///
    /// Call it only on a confirmed release. A release whose outcome is unknown must leave the
    /// token exactly where it is: discarding it on a maybe would strand a lock that is still held
    /// with no token left to release it, which is the one failure CR-030's token exists to
    /// prevent. Clearing a resource this client holds no token for is not an error.
    async fn clear_ownership(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<(), ProtocolError>;

    /// Forget the tokens for a batch of resources the server has confirmed released.
    ///
    /// Defaulted to a loop over [`Self::clear_ownership`], and overridden by any implementation
    /// whose single clear rewrites a whole document: a release covering a branch confirms
    /// hundreds of resources at once, and clearing them one at a time makes that quadratic.
    ///
    /// The batch carries [`Self::clear_ownership`]'s rule unchanged, per resource: name only what
    /// the server confirmed. A release whose outcome is unknown belongs in no batch.
    async fn clear_ownership_batch(
        &self,
        resources: &[(Context, Hash)],
    ) -> Result<(), ProtocolError> {
        for (branch, resource_hash) in resources {
            self.clear_ownership(branch, resource_hash).await?;
        }
        Ok(())
    }

    /// Settle an attempt.
    ///
    /// Moves the record to [`AttemptState::Resolved`] and *keeps* it. Nothing removes a record:
    /// there is no expiry, no eviction, and no delete. An unresolved attempt is precisely the one
    /// that must not be forgotten, and a resolved one is the lineage that stops a late callback
    /// or a restored snapshot from offering a retry for a mutation that already happened.
    ///
    /// **This touches no lock ownership, and that is load-bearing rather than an omission.** It
    /// used to drop every ownership row held by the resolving attempt, on the reasoning that a
    /// settled attempt should not still be holding something. That conflates two lifetimes. An
    /// attempt is settled when its outcome is known; a lock is held until somebody releases it,
    /// and outliving the attempt that took it is the entire purpose of a lock.
    ///
    /// The cost of the old rule was not theoretical. The moment a lock acquire adopts the
    /// dispatch attempt id — which is the natural fix for the receipt-matching gap pinned in
    /// `lore-revision`'s acquire path — a decisive `NotApplied` resolution would delete the
    /// ownership token for a lock the caller still holds, leaving a row only an administrator can
    /// release. That is precisely the failure CR-030's token exists to prevent, reached
    /// sideways. Found by the lock lane before either half shipped.
    ///
    /// Ownership rows are removed by [`Self::clear_ownership`] alone, and only on a release the
    /// server confirmed.
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

    async fn clear_ownership(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<(), ProtocolError> {
        self.ownership
            .lock()
            .retain(|held| !(held.branch == *branch && held.resource_hash == *resource_hash));
        Ok(())
    }

    async fn resolve(
        &self,
        attempt: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        if let Some(stored) = self.attempts.lock().get_mut(&attempt.as_uuid()) {
            stored.state = AttemptState::Resolved(resolution);
        }
        // Ownership is deliberately untouched; see the trait method's docs. A lock outlives the
        // attempt that took it, and dropping the token here would strand a held lock.
        Ok(())
    }
}

/// CR-030: [`OwnershipToken`]'s three-way wire decode, and the redaction every type carrying one
/// promises. Independent of any [`AttemptStore`] implementation -- these are pure, offline
/// properties of the newtype itself.
#[cfg(test)]
mod ownership_token_tests {
    use super::*;

    fn token(fill: u8) -> OwnershipToken {
        OwnershipToken::from_wire(&[fill; OwnershipToken::LEN])
            .expect("32 bytes must decode without error")
            .expect("32 bytes must produce a token, not None")
    }

    /// An unfenced cell (or a legacy read path) returns an empty token, and that is not an
    /// error -- it is the "no fenced authority here" answer.
    #[test]
    fn from_wire_empty_is_ok_none() {
        assert_eq!(
            OwnershipToken::from_wire(&[]).expect("empty must not error"),
            None
        );
    }

    /// The exact width CR-030 mints round-trips byte for byte.
    #[test]
    fn from_wire_exact_width_is_some_and_preserves_the_bytes() {
        let bytes = [0x42u8; OwnershipToken::LEN];
        let decoded = OwnershipToken::from_wire(&bytes)
            .expect("exact width must not error")
            .expect("exact width must produce a token");
        assert_eq!(decoded.as_bytes().as_ref(), bytes.as_slice());
    }

    /// Any width other than 0 or exactly 32 is an error, never a silently dropped token -- a
    /// token this client cannot hold onto is a lock it cannot release, and `Ok(None)` here would
    /// make that failure indistinguishable from an ordinary unfenced acquire.
    #[test]
    fn from_wire_wrong_width_is_an_error_not_a_silently_dropped_token() {
        for bad_len in [1usize, OwnershipToken::LEN - 1, OwnershipToken::LEN + 1, 64] {
            let bytes = vec![0x11u8; bad_len];
            let error = OwnershipToken::from_wire(&bytes)
                .expect_err(&format!("width {bad_len} must be refused"));
            assert!(
                error.is_internal(),
                "a malformed token width must surface as an ordinary internal error, not a \
                 retryable/disconnect-shaped one a caller might treat as safe to retry: {error:?}"
            );
        }
    }

    /// The whole reason for the newtype: formatting it never prints the bearer secret.
    #[test]
    fn debug_never_prints_the_token_bytes() {
        let formatted = format!("{:?}", token(0xAB));
        assert_eq!(formatted, "OwnershipToken(<redacted>)");
    }

    /// [`LockOwnership`]'s hand-written `Debug` must redact the token while leaving the other
    /// fields legible -- the whole point of writing it by hand instead of deriving it.
    #[test]
    fn lock_ownership_debug_redacts_the_token_but_keeps_the_other_fields_readable() {
        let ownership = LockOwnership {
            attempt_id: AttemptId::new(),
            branch: Context::from([0x11u8; 16]),
            resource_hash: Hash::from([0x22u8; 32]),
            token: token(0xAB),
        };
        let formatted = format!("{ownership:?}");

        assert!(
            formatted.contains("OwnershipToken(<redacted>)"),
            "the token field must redact: {formatted}"
        );
        assert!(
            !formatted.contains("\\xab\\xab\\xab\\xab"),
            "the raw token bytes must never leak through the struct's own Debug: {formatted}"
        );
        assert!(
            formatted.contains("attempt_id") && formatted.contains("resource_hash"),
            "redacting the token must not swallow the struct's other fields: {formatted}"
        );
    }
}
