// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// WP-120 Phase 4: the unknown outcome keeps code 193 all the way to the FFI boundary.
//
// The defect this exists to catch is not a wrong number, it is a *lost* one. An
// `EventError::translated()` impl whose body is a blanket `LoreError::Internal`, or a match with
// a `_` arm and no `OutcomeUnknown` case, compiles perfectly and reports a dispatched mutation
// whose outcome nobody knows as `-1` — indistinguishable, to a C caller, from an operation that
// provably did not happen. Eleven impls in this crate were exactly that shape before WP-120.
//
// So these tests walk the ladder rather than checking one value: the discrete error's own code,
// the code after it has been forwarded into an error set, and the `LoreError` the set translates
// to. A regression at any rung is a caller being told the wrong thing about durable state.
//
// The lock family leads because it is the highest-consequence one: `LockService.Lock` and
// `LockService.Unlock` are both `MutableNoReplay`, so a lost lock or unlock is precisely the
// case a caller must never resolve by retrying.

use lore_base::error::Disconnected;
use lore_base::error::OutcomeUnknown;
use lore_base::types::Address;
use lore_error_set::FfiError;
use lore_revision::branch::BranchError;
use lore_revision::event::EventError;
use lore_revision::interface::LoreError;
use lore_revision::lock::file::acquire::AcquireError;
use lore_revision::lock::file::release::ReleaseError;
use lore_storage::error::protocol_error_to_storage;
use lore_transport::ProtocolError;

/// The code allocated in `lore_base::error`, which everything below has to agree with.
const OUTCOME_UNKNOWN: i32 = 193;

fn unknown() -> OutcomeUnknown {
    OutcomeUnknown {
        operation: "LockService.Lock".to_string(),
        attempt_id: "0199a0b1-c2d3-7e4f-8a9b-0c1d2e3f4a5b".to_string(),
    }
}

/// What every rung of the ladder below must report for [`unknown`], via
/// [`lore_error_set::FfiError::outcome_identity`].
const EXPECTED_IDENTITY: (&str, &str) =
    ("LockService.Lock", "0199a0b1-c2d3-7e4f-8a9b-0c1d2e3f4a5b");

#[test]
fn the_discrete_error_carries_the_allocated_code() {
    assert_eq!(unknown().ffi_code(), OUTCOME_UNKNOWN);
}

/// A lost `Lock` keeps its own code rather than collapsing into `Internal`.
#[test]
fn a_lost_lock_acquire_reaches_the_ffi_boundary_as_outcome_unknown() {
    let error = AcquireError::from(unknown());

    assert_eq!(error.ffi_code(), OUTCOME_UNKNOWN);
    assert!(
        error.translated() == LoreError::OutcomeUnknown,
        "a dispatched Lock whose response was lost must not translate to {:?}",
        error.translated() as i32,
    );
}

/// And a lost `Unlock`, which is the same hazard from the other direction: reported as a
/// failure, a caller re-runs the release; reported as a success, it stops holding the lock it
/// may still own.
#[test]
fn a_lost_lock_release_reaches_the_ffi_boundary_as_outcome_unknown() {
    let error = ReleaseError::from(unknown());

    assert_eq!(error.ffi_code(), OUTCOME_UNKNOWN);
    assert!(error.translated() == LoreError::OutcomeUnknown);
}

/// The negative control. Without it, a `translated()` that returned `OutcomeUnknown`
/// unconditionally would satisfy every test above.
///
/// It asserts `Internal`, and that is worth stating rather than glossing: this impl reports
/// *every* non-unknown variant as `Internal`, including an ordinary disconnect. That is
/// pre-existing — the impl was a blanket `LoreError::Internal` before WP-120 carved the unknown
/// out of it — and WP-120 deliberately did not widen its scope to reclassify the rest. The
/// value of pinning it here is that it proves the carve-out is a carve-out: one variant moved,
/// the others did not.
#[test]
fn a_neighbouring_variant_is_not_swept_into_the_unknown() {
    let error = AcquireError::from(Disconnected);

    assert!(
        error.translated() == LoreError::Internal,
        "this impl still reports every non-unknown variant as Internal; only the unknown moved",
    );
    assert_ne!(error.ffi_code(), OUTCOME_UNKNOWN);
}

/// The internal error is what the eleven blanket impls used to return for everything. Pinning it
/// separately means a future edit cannot make this file pass by widening `Internal` to cover the
/// unknown again.
#[test]
fn internal_and_outcome_unknown_stay_distinct() {
    assert_ne!(
        LoreError::Internal as i32,
        LoreError::OutcomeUnknown as i32,
        "the whole point of the variant is that it is not the catch-all",
    );
    assert_eq!(LoreError::OutcomeUnknown as i32, OUTCOME_UNKNOWN);
}

// -------------------------------------------------------------------------------------------
// The set-ladder pin for `FfiError::outcome_identity`. Every impl above proves the *code*
// (193) and the *classification* (`translated() == OutcomeUnknown`) survive; none of them
// proves the operation and attempt id travel with it. `outcome_identity` is defaulted to
// `None` on the trait, and an `#[error_set]`-generated impl delegates to it automatically
// (`codegen.rs`'s `identity_arms`) -- but a *hand-written* conversion between sets, such as
// `protocol_error_to_storage`, has no macro to lean on and can drop the identity on the floor
// the same way a blanket `_ => Internal` used to drop the code. Three rungs, each a different
// kind of delegation: an auto-generated `From` (`ProtocolError`), a hand-written mapping
// function (`StorageError`), and a hand-written `EventError::translated()` at the FFI boundary
// itself (`BranchError`).
// -------------------------------------------------------------------------------------------

/// Rung 0, completing the Lock family's own ladder: the code and the classification were
/// already pinned above; this is the identity.
#[test]
fn lock_acquire_and_release_report_the_operation_and_attempt_id() {
    assert_eq!(
        AcquireError::from(unknown()).outcome_identity(),
        Some(EXPECTED_IDENTITY)
    );
    assert_eq!(
        ReleaseError::from(unknown()).outcome_identity(),
        Some(EXPECTED_IDENTITY)
    );
}

/// Rung 1: `lore-transport`'s own error set. `ProtocolError::OutcomeUnknown` is what every
/// higher rung ultimately converts, so if the identity is lost here nothing above can recover
/// it.
#[test]
fn protocol_error_reports_the_operation_and_attempt_id() {
    let error = ProtocolError::from(unknown());
    assert_eq!(error.ffi_code(), OUTCOME_UNKNOWN);
    assert_eq!(error.outcome_identity(), Some(EXPECTED_IDENTITY));
}

/// The negative control for rung 1: an ordinary connectivity error carries no identity to
/// report, and must not be answered with a stale or default one.
#[test]
fn protocol_errors_neighbouring_variant_has_no_identity() {
    let error = ProtocolError::from(Disconnected);
    assert_eq!(error.outcome_identity(), None);
}

/// Rung 2: `lore-storage`'s `protocol_error_to_storage`, a hand-written mapping function
/// rather than a macro-generated `From`. This is exactly the shape of code that dropped the
/// FFI code into `Internal` before WP-120 -- an early, unconditional match arm ahead of the
/// explicit `OutcomeUnknown` check would compile cleanly and silently lose the identity too.
#[test]
fn storage_error_reports_the_operation_and_attempt_id_through_the_manual_protocol_mapping() {
    let storage_error =
        protocol_error_to_storage(ProtocolError::from(unknown()), Address::default());
    assert_eq!(storage_error.ffi_code(), OUTCOME_UNKNOWN);
    assert_eq!(storage_error.outcome_identity(), Some(EXPECTED_IDENTITY));
}

/// The negative control for rung 2: a mapped disconnect carries no identity, proving the
/// positive case above is not a default that answers `Some` for everything.
#[test]
fn storage_errors_neighbouring_mapped_variant_has_no_identity() {
    let storage_error =
        protocol_error_to_storage(ProtocolError::from(Disconnected), Address::default());
    assert_eq!(storage_error.outcome_identity(), None);
}

/// Rung 3, at the FFI boundary itself: `BranchError` is one of the eleven `EventError` impls
/// WP-120 had to carve `OutcomeUnknown` out of, and its `translated()` is hand-written, not
/// macro-generated. Both the classification and the identity have to survive it.
#[test]
fn branch_error_reports_the_operation_and_attempt_id_and_translates_to_outcome_unknown() {
    let error = BranchError::from(unknown());
    assert_eq!(error.ffi_code(), OUTCOME_UNKNOWN);
    assert_eq!(error.outcome_identity(), Some(EXPECTED_IDENTITY));
    assert!(
        error.translated() == LoreError::OutcomeUnknown,
        "a dispatched branch mutation whose response was lost must not translate to {:?}",
        error.translated() as i32,
    );
}

/// The negative control for rung 3, mirroring `a_neighbouring_variant_is_not_swept_into_the_unknown`
/// above: an ordinary `BranchError` variant carries no identity and must not translate to
/// `OutcomeUnknown` just because the set contains that variant somewhere.
#[test]
fn branch_errors_neighbouring_variant_has_no_identity_and_does_not_translate_to_outcome_unknown() {
    let error = BranchError::from(Disconnected);
    assert_eq!(error.outcome_identity(), None);
    assert_ne!(error.translated() as i32, LoreError::OutcomeUnknown as i32);
}
