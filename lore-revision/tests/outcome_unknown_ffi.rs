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
use lore_error_set::FfiError;
use lore_revision::event::EventError;
use lore_revision::interface::LoreError;
use lore_revision::lock::file::acquire::AcquireError;
use lore_revision::lock::file::release::ReleaseError;

/// The code allocated in `lore_base::error`, which everything below has to agree with.
const OUTCOME_UNKNOWN: i32 = 193;

fn unknown() -> OutcomeUnknown {
    OutcomeUnknown {
        operation: "LockService.Lock".to_string(),
        attempt_id: "0199a0b1-c2d3-7e4f-8a9b-0c1d2e3f4a5b".to_string(),
    }
}

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
