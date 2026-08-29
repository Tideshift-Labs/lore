// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The domain-key bypass guard for the generic mutable path (CR-029 Phase 3).
//!
//! Seven public entry points accept an **arbitrary wire `KeyType`** and write it
//! with no handler-level domain logic at all: the v0 and v1 gRPC
//! `MutableStore`/`MutableCompareAndSwap` pairs, the QUIC `urc/0.2`
//! `MutableStore`/`MutableCas` commands, and the QUIC `lore-storage/0.4`
//! equivalents (worklog 254 §A.7). Authorization on all seven is repository-level
//! `write` only, with no key-type restriction — and `require_permission` returns
//! `Ok` outright when the request carries no token, so with auth off they are
//! wide open.
//!
//! **The guard therefore lives here, in `lore-postgres`, not in the seven
//! handlers.** Two of them are QUIC and use a different authorization path from
//! the gRPC five, so a handler-level check would have to be written twice and
//! kept in step forever. One check at the store is reached by all seven.
//!
//! No trait default, no downcast, no silent fallback: a rejected write returns
//! an explicit error naming the key type. A guard that quietly degraded to
//! "allow" on an unrecognised configuration would be worse than no guard, because
//! it would read as protection in a review.
//!
//! ## `Instance` is fenced deliberately
//!
//! `KeyType::Instance` has **zero server writers** at this baseline: every
//! `register_instance` call site is client-side and requires a filesystem path,
//! which `new_server_context` never has. But a client can still write an
//! `Instance`-typed key into a shared cell through any of those seven RPCs,
//! because they pass the wire `KeyType` through untouched. So "no server writer"
//! is not "cannot be written server-side", and worklog 254 §A.10 requires the
//! disposition to be stated rather than left to the shape of an allowlist. It is
//! fenced.
//!
//! `KeyType::Resolve` is **out**: it is the content-address resolution map,
//! written only by `PutResolved`/`GetResolved`, never enumerated by
//! `repository::list_local` or `branch::list`, and carries no lifecycle or
//! indexing role. `KeyType::Untyped` is out for the same reason — the revision-
//! step and revision-list keys it covers are acceleration, outside the
//! transaction by CR-029's own boundary.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use lore_base::types::KeyType;

/// Whether domain enforcement is active for this process.
///
/// Shared with the domain store so readiness can flip it once, at the point the
/// cutover marker and projection checks have passed, rather than every write
/// re-reading `lore_domain_schema_state`.
#[derive(Debug, Clone, Default)]
pub struct DomainEnforcement(Arc<AtomicBool>);

impl DomainEnforcement {
    /// A handle that starts disabled. Enforcement is opt-in and fails closed:
    /// a cell that never completes backfill never turns this on.
    pub fn disabled() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Turn enforcement on. Called only after
    /// [`crate::domain::store::PostgresDomainStore::enable_enforcement`] has
    /// verified the cutover marker, the residue classification, and the
    /// database identity.
    pub fn enable(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Turn enforcement off, for the documented rollback path.
    pub fn disable(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Whether writes through the generic mutable path are currently fenced.
    pub fn is_enabled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Whether this key type is owned by the CR-029 domain coordinator.
///
/// Matching on the enum rather than on a numeric allowlist means a new
/// `KeyType` upstream is a compile error here, and whoever adds it has to make
/// the in/out decision explicitly.
pub fn is_domain_owned(key_type: KeyType) -> bool {
    match key_type {
        KeyType::RepositoryId
        | KeyType::RepositoryMetadata
        | KeyType::BranchId
        | KeyType::BranchMetadata
        | KeyType::BranchLatestPointer
        // Zero server writers, but reachable from a client through the seven
        // generic RPCs. See the module docs.
        | KeyType::Instance => true,
        // The content-address resolution map, and the acceleration keys. Neither
        // participates in repository or branch lifecycle or indexing.
        KeyType::Resolve | KeyType::Untyped => false,
    }
}

/// The error text a fenced write returns.
///
/// It names the key type and points at the coordinator, because the operator
/// reading it in a log is almost always looking at a client that is still
/// writing domain keys directly and needs to know which one.
pub fn rejection_message(key_type: KeyType) -> String {
    format!(
        "generic mutable-store write rejected: {key_type:?} is a CR-029 domain-owned key type \
         and must be written through the domain transaction coordinator, not the generic \
         MutableStore path"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_five_lifecycle_key_types_are_fenced() {
        for kt in [
            KeyType::RepositoryId,
            KeyType::RepositoryMetadata,
            KeyType::BranchId,
            KeyType::BranchMetadata,
            KeyType::BranchLatestPointer,
        ] {
            assert!(is_domain_owned(kt), "{kt:?} must be fenced");
        }
    }

    #[test]
    fn instance_is_fenced_even_though_no_server_writes_it() {
        assert!(is_domain_owned(KeyType::Instance));
    }

    #[test]
    fn resolve_and_untyped_are_not_fenced() {
        assert!(!is_domain_owned(KeyType::Resolve));
        assert!(!is_domain_owned(KeyType::Untyped));
    }

    #[test]
    fn enforcement_starts_disabled_and_is_reversible() {
        let e = DomainEnforcement::disabled();
        assert!(!e.is_enabled());
        e.enable();
        assert!(e.is_enabled());
        e.disable();
        assert!(!e.is_enabled());
    }

    #[test]
    fn enforcement_handles_share_one_flag() {
        // The store and the mutable-store hold clones of the same handle; a
        // clone that carried its own flag would leave half the process
        // unenforced.
        let a = DomainEnforcement::disabled();
        let b = a.clone();
        a.enable();
        assert!(b.is_enabled());
    }

    #[test]
    fn the_rejection_names_the_key_type() {
        let msg = rejection_message(KeyType::BranchLatestPointer);
        assert!(msg.contains("BranchLatestPointer"), "{msg}");
    }
}
