// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Exact local cleanup of one staged epoch.
//!
//! This is the [`StagedEpochCleanup`] implementation the obliterate path
//! already consumes (`store/immutable_store.rs`'s staged arms in
//! `load_obliterate_representation` and `purge_obliterate_target`). The trait
//! predates this module and its doc comment already names this seam as its
//! supplier, so no new cleanup trait is introduced.
//!
//! # This module never decides that bytes are unprotected
//!
//! It acts only on a [`FragmentPurgeTarget`] the coordinator computed under the
//! fragment head lock, after `obliterate_blocked_until_locked` folded every live
//! staged reader lease's deadline into the intent's `blocked_until`. The
//! obliterate loop sleeps on `FragmentObliterateBegin::Blocked` rather than
//! reaching here. So the deletion barrier is upheld by construction: this module
//! has no lease query, no clock comparison, and no database resource with which
//! to acquire either.
//!
//! Two further guards, both local:
//!
//! - a target whose authority is not [`EpochAuthority::Staged`] is refused. A
//!   `Remote` target names an object in the provider's keyspace, and unlinking
//!   anything for it would be acting on a key this tier does not own.
//! - the path unlinked is the one **derived** from the target's own typed
//!   `(hash, epoch)`, and the target's stored key must be byte-equal to that
//!   derivation. A target naming a different epoch therefore cannot reach
//!   another epoch's bytes, which is what keeps a quarantined predecessor and
//!   its successor separable.
//!
//! # Absence
//!
//! `purge_exact` treats an already-absent file as success: a purge retried after
//! a crash must converge, and a second unlink of a path this process already
//! removed is the expected case, not a fault.
//!
//! `read_exact` is the opposite shape, because the trait's contract makes `None`
//! decisive: only a real `ENOENT` under a root this process has proven it owns
//! yields `Ok(None)`. Every uncertain condition — unset root, lost mount, wrong
//! device — is an error, which keeps the head deleting instead of concluding a
//! child set is empty.

use async_trait::async_trait;
use bytes::Bytes;
use lore_storage::StoreError;

use super::StagedRead;
use super::WriteBehindError;
use super::WriteBehindStage;
use crate::domain::fragments::EpochAuthority;
use crate::domain::fragments::FragmentPurgeTarget;
use crate::store::immutable_store::StagedEpochCleanup;

#[async_trait]
impl StagedEpochCleanup for WriteBehindStage {
    async fn read_exact(&self, target: &FragmentPurgeTarget) -> Result<Option<Bytes>, StoreError> {
        require_staged(target)?;
        match self
            .read_staged(target.hash(), target.epoch(), target.object_key())
            .await
        {
            StagedRead::Found(bytes) => Ok(Some(bytes)),
            StagedRead::Absent => Ok(None),
            StagedRead::Unavailable(error) => Err(error.store_error()),
        }
    }

    async fn purge_exact(&self, target: &FragmentPurgeTarget) -> Result<(), StoreError> {
        require_staged(target)?;
        let resolved = self
            .root()
            .resolve(target.hash(), target.epoch(), target.object_key())
            .map_err(WriteBehindError::store_error)?;
        self.root()
            .remove_regular(&resolved)
            .await
            .map_err(WriteBehindError::store_error)
    }
}

/// Refuse any authority but `Staged`.
///
/// Internal rather than retryable: a `Remote` target reaching the staging tier
/// means the obliterate path dispatched on authority incorrectly, and no number
/// of retries changes which keyspace a key belongs to.
fn require_staged(target: &FragmentPurgeTarget) -> Result<(), StoreError> {
    if target.authority() == EpochAuthority::Staged {
        return Ok(());
    }
    Err(StoreError::internal(
        "write-behind staging cleanup received a non-staged purge target",
    ))
}
