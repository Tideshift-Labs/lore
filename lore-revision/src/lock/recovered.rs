// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! What a recovered lock receipt leaves in the repository's ownership store (WP-120).
//!
//! A live acquire keeps every token it was granted (`acquire::record_batch_ownership`), and a
//! confirmed release clears them. When the answer was lost, recovery reads the receipt instead,
//! and it must leave the same ownership behind. A lock settled as applied with no token kept is a
//! lock its owner cannot release; only an administrator's force release can clear it.
//!
//! Run this before the child is resolved. A failure here keeps the child unresolved, so the
//! repository stays blocked rather than settling an acquire whose token it could not keep.

use std::collections::HashSet;
use std::path::Path;

use lore_transport::DomainAttemptReceipt;
use lore_transport::DomainReceiptOutcome;
use lore_transport::DomainReceiptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::caller_operation::recorded_lock_resources;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;

use crate::attempt_store::RepositoryAttemptStore;
use crate::lore::BranchId;
use crate::lore::Hash;

/// Leave the ownership a live lock verb would have left, for one attempt settled `Applied`.
///
/// `journal` is the store that holds the child; the ownership store is the one the lock verbs
/// derive from the repository at `root` (its dot directory's `attempts`), exactly as a live acquire
/// or release uses it. Anything other than a committed `Applied` lock acquire or release is left
/// alone.
pub async fn settle_recovered_ownership(
    root: &Path,
    journal: &RepositoryAttemptStore,
    attempt: &AttemptId,
    recorded_rpc: &str,
    receipt: &DomainAttemptReceipt,
) -> Result<(), ProtocolError> {
    if !matches!(
        receipt.state,
        DomainReceiptState::Committed {
            outcome: DomainReceiptOutcome::Applied,
            ..
        }
    ) {
        return Ok(());
    }
    let acquire = recorded_rpc == GrpcRpc::LockLock.wire_name();
    let release = recorded_rpc == GrpcRpc::LockUnlock.wire_name()
        || recorded_rpc == GrpcRpc::LockForceUnlock.wire_name();
    if !acquire && !release {
        return Ok(());
    }
    let (journalled_rpc, canonical) = journal.managed_request(attempt).await?;
    if journalled_rpc != recorded_rpc {
        return Err(ProtocolError::internal(
            "the journalled request names a different RPC than its child",
        ));
    }
    let recorded = recorded_lock_resources(recorded_rpc, &canonical)?;
    let dot_directory = crate::repository::get_dot_lore_path(root)
        .map_err(|error| ProtocolError::internal(error.to_string()))?;
    let ownership = RepositoryAttemptStore::in_directory(dot_directory);

    if release {
        // A fenced release is all or nothing: an applied receipt released every requested row.
        // Only a row still holding the token the release presented is cleared, so a row acquired
        // again since then, or a second settlement of the same receipt, keeps its newer token. A
        // tokenless (force) release names no token, and this client held none for that row.
        let released = recorded
            .into_iter()
            .filter_map(|resource| {
                resource
                    .expected_ownership_token
                    .map(|token| (resource.resource.branch, resource.resource.hash, token))
            })
            .collect::<Vec<_>>();
        return ownership.clear_ownership_matching(&released).await;
    }
    let requested = recorded
        .into_iter()
        .map(|resource| (resource.resource.branch, resource.resource.hash))
        .collect::<HashSet<(BranchId, Hash)>>();

    // A renewal mints new tokens. A current server returns them on the receipt, and they replace
    // the held ones below. A server from before that returns none, so they cannot be recovered
    // here, and the tokens this client holds are now stale.
    if receipt.method == "lock.renew" && receipt.acquired_locks.is_empty() {
        crate::lore_warn!(
            "Lock renewal {attempt} settled applied without its new ownership tokens; the held \
             tokens may no longer release these locks"
        );
        return Ok(());
    }

    // The server returns these only to the attempt's own principal. Bind them here too, to the
    // subject the attempt was dispatched under and to the resources it asked for, before keeping
    // any of them.
    let subject = journal
        .recovery_context(attempt)
        .await?
        .authenticated_subject;
    let mut granted = HashSet::with_capacity(receipt.acquired_locks.len());
    let mut records = Vec::with_capacity(receipt.acquired_locks.len());
    for acquired in &receipt.acquired_locks {
        let key = (acquired.lock.resource.branch, acquired.lock.resource.hash);
        if acquired.lock.owner != subject {
            return Err(ProtocolError::internal(
                "the acquire receipt names a lock owned by another principal",
            ));
        }
        if !requested.contains(&key) {
            return Err(ProtocolError::internal(
                "the acquire receipt names a lock this attempt did not request",
            ));
        }
        let Some(token) = acquired.ownership_token.clone() else {
            return Err(ProtocolError::internal(
                "the acquire receipt names a lock without its ownership token",
            ));
        };
        granted.insert(key);
        records.push(LockOwnership {
            attempt_id: *attempt,
            branch: key.0,
            resource_hash: key.1,
            token,
        });
    }
    // A fenced acquire grants every requested resource or none, so a gap means a token is lost.
    if granted != requested {
        return Err(ProtocolError::internal(
            "the acquire receipt does not return a token for every requested lock",
        ));
    }
    for record in &records {
        ownership.record_ownership(record).await?;
    }
    Ok(())
}
