// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-120 refresh reads: the authoritative generations that `RepositoryGet`,
//! `BranchGet` and a branch-scoped lock `Query` attach to their responses.
//!
//! Every function here answers `None` rather than a placeholder when it has no
//! authority to answer: no domain context (not Postgres mode), a context whose
//! enforcement is off (domain rows are not yet the source of truth), a lock
//! service that is not on the fenced route, or an absent row. A client treats
//! `None` as "refresh unconditionally", so a fake `0` would be the one wrong
//! answer: it could compare equal to a value the client already holds.
//!
//! Callers read the generation BEFORE the projection data they return. A
//! mutation landing between the two reads then leaves the client holding a
//! stale generation beside fresh data, which costs one extra refresh; the
//! other order could pair a fresh generation with stale data and hide a change.
//!
//! A failed generation read never fails the RPC. The generation is an
//! optimization hint, so a read error logs a warning and answers `None`: the
//! client refreshes unconditionally and the projection read still runs.

use std::fmt::Display;
use std::sync::Arc;

use lore_postgres::domain::locks::PostgresLockCoordinator;
use tracing::warn;

use super::DomainContext;

/// The three lock-namespace counters, converted to the wire's unsigned range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockNamespaceGeneration {
    pub repository_lock_generation: u64,
    pub branch_lock_generation: u64,
    pub last_applied_fence: u64,
}

impl From<LockNamespaceGeneration> for lore_proto::lock::LockNamespaceGeneration {
    fn from(value: LockNamespaceGeneration) -> Self {
        Self {
            repository_lock_generation: value.repository_lock_generation,
            branch_lock_generation: value.branch_lock_generation,
            last_applied_fence: value.last_applied_fence,
        }
    }
}

/// The domain context, only when its rows are authoritative for this cell.
fn armed(domain: Option<&Arc<DomainContext>>) -> Option<&Arc<DomainContext>> {
    domain.filter(|domain| domain.enforcement_enabled())
}

/// Whether this cell can answer a domain generation at all. Lets a caller skip
/// the extra work of resolving an identity it would only use for one.
pub fn is_authoritative(domain: Option<&Arc<DomainContext>>) -> bool {
    armed(domain).is_some()
}

/// A stored generation is a non-negative `BIGINT`. A negative value is not a
/// generation the client can compare against, so it reads as absent.
fn to_wire(generation: i64) -> Option<u64> {
    u64::try_from(generation).ok()
}

/// A failed generation read degrades to `None` with one warning. Ids are
/// logged as hex; the error is the domain error's display, which carries no
/// credentials.
fn degrade<T, E: Display>(
    result: Result<Option<T>, E>,
    what: &str,
    repository_id: &[u8],
) -> Option<T> {
    result.unwrap_or_else(|error| {
        warn!(
            repository_id = %hex::encode(repository_id),
            "WP-120 {what} read failed; answering no generation: {error}"
        );
        None
    })
}

/// The repository's domain generation, or `None` without authority or when
/// the read fails.
pub async fn repository_generation(
    domain: Option<&Arc<DomainContext>>,
    repository_id: &[u8],
) -> Option<u64> {
    let domain = armed(domain)?;
    let snapshot = domain.store().repository_snapshot(repository_id).await;
    degrade(snapshot, "repository generation", repository_id)
        .and_then(|snapshot| to_wire(snapshot.generation))
}

/// The branch's domain generation, or `None` without authority or when the
/// read fails.
pub async fn branch_generation(
    domain: Option<&Arc<DomainContext>>,
    repository_id: &[u8],
    branch_id: &[u8],
) -> Option<u64> {
    let domain = armed(domain)?;
    let snapshot = domain
        .store()
        .branch_snapshot(repository_id, branch_id)
        .await;
    degrade(snapshot, "branch generation", repository_id)
        .and_then(|snapshot| to_wire(snapshot.generation))
}

/// One branch namespace's lock generation, read from the fenced lock
/// authority. `None` when the namespace row is absent, a counter is out of
/// the wire's range, or the read fails.
pub async fn lock_namespace_generation(
    coordinator: &PostgresLockCoordinator,
    repository_id: &[u8],
    branch_id: &[u8],
) -> Option<LockNamespaceGeneration> {
    let witness = coordinator
        .namespace_generation(repository_id, branch_id)
        .await;
    let witness = degrade(witness, "lock namespace generation", repository_id)?;
    Some(LockNamespaceGeneration {
        repository_lock_generation: to_wire(witness.repository_lock_generation)?,
        branch_lock_generation: to_wire(witness.branch_lock_generation)?,
        last_applied_fence: to_wire(witness.branch_lock_namespace_last_applied_fence)?,
    })
}
