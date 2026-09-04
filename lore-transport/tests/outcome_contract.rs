// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// WP-120 Phase 2 public outcome fixtures.
//
// [CLIENT]-class: `lore-transport` is a client-path crate. Pure, offline fixtures, no live
// server -- an external test target (not an inline `#[cfg(test)] mod`), matching
// `replay_contract.rs`'s own convention, so this file exercises ONLY the crate's PUBLIC surface:
// the same surface any embedding caller (lore-storage, lore-revision, and eventually WP-120's own
// downstream consumers) links against.
//
// `outcome.rs`'s own in-module `#[cfg(test)] mod tests` already pins the mapping's internal
// logic in detail (resolve/is_outcome_unknown/attempt-id ordering/GrpcRpc-vs-QUIC agreement).
// This file does not duplicate that. It proves two things the in-module tests cannot, because
// they run with crate-internal visibility:
//
//   1. reachability: every symbol a downstream caller needs is actually exported from the crate
//      root, not merely `pub` inside `outcome.rs`;
//   2. the tonic::Status round trip: `ProtocolError::OutcomeUnknown` -> `tonic::Status` -> back to
//      `ProtocolError::OutcomeUnknown`, which `error.rs`'s own tests do not cover (they only pin
//      the pre-existing, unmarked-status arms), and the companion negative case -- an ordinary
//      unmarked `tonic::Code::Unknown` must still fall back to `Disconnected`, not silently
//      become `OutcomeUnknown` out of thin air. The contract is explicit that the unknown is
//      upgraded only by the server's own marker or the caller's local dispatch tracking, never
//      inferred from the bare code.

use lore_transport::AttemptId;
use lore_transport::OUTCOME_UNKNOWN_CAPABILITY_V1;
use lore_transport::OutcomeUnknown as TransportOutcomeUnknown;
use lore_transport::ProtocolError;
use lore_transport::TRANSPORT_CAPABILITIES;
use lore_transport::grpc_replay_class;
use lore_transport::outcome_unknown;
use lore_transport::resolve;
use lore_transport::supports_outcome_unknown_v1;

/// Reachability: every symbol a downstream caller needs, addressed through nothing but the
/// crate root. If any of these were only `pub` inside `outcome.rs` without a crate-root
/// re-export, this file would fail to compile -- that is the proof, not any runtime assertion.
#[test]
fn the_public_outcome_surface_is_reachable_through_the_crate_root() {
    let attempt = AttemptId::new();
    let _ = attempt.as_uuid();
    let _ = attempt.to_string();

    let error = outcome_unknown("StorageService.Put", &attempt);
    assert!(error.is_outcome_unknown());

    let outcome: lore_transport::MutableOutcome<()> =
        lore_transport::MutableOutcome::Unknown(TransportOutcomeUnknown { command: "put" });
    let resolved = resolve(outcome, "StorageService.Put", &attempt);
    assert!(resolved.is_err());

    let rpc = lore_transport::GrpcRpc::StoragePut;
    let _ = grpc_replay_class(rpc);
    let _ = rpc.wire_name();

    assert!(supports_outcome_unknown_v1());
    assert!(TRANSPORT_CAPABILITIES.contains(&OUTCOME_UNKNOWN_CAPABILITY_V1));
}

/// The whole round trip: a public `OutcomeUnknown` converted to a `tonic::Status` and back must
/// yield the same operation and attempt, not just "some error that happens to look similar".
/// This is the exact seam `error.rs`'s own `From<ProtocolError> for tonic::Status` and
/// `From<tonic::Status> for ProtocolError` impls both touch; a bug in either direction shows up
/// here as a lost or corrupted field, not as a different variant.
#[test]
fn outcome_unknown_round_trips_through_a_tonic_status_with_its_operation_and_attempt() {
    let attempt = AttemptId::new();
    let original = outcome_unknown("RevisionService.BranchPush", &attempt);

    let status: tonic::Status = original.into();
    assert_eq!(
        status.code(),
        tonic::Code::Unknown,
        "the wire status for an unknown outcome must be Unknown, not Unavailable/Internal -- \
         those already mean something else (Disconnected/Internal) and reusing them would make \
         the marker headers the only signal, silently breaking any intermediary that only reads \
         the code"
    );

    let round_tripped = ProtocolError::from(status);
    assert!(
        round_tripped.is_outcome_unknown(),
        "a status built from OutcomeUnknown must decode back to OutcomeUnknown: {round_tripped:?}"
    );
    let decoded = round_tripped
        .as_outcome_unknown()
        .expect("just asserted is_outcome_unknown");
    assert_eq!(decoded.operation, "RevisionService.BranchPush");
    assert_eq!(decoded.attempt_id, attempt.to_string());
}

/// The companion negative control. An ORDINARY server error that happens to carry
/// `tonic::Code::Unknown` but sets none of the marker metadata must still classify as
/// `Disconnected` -- exactly the pre-existing behavior for every other unmapped/ambiguous
/// status. If this test is ever made to pass by making `From<tonic::Status>` treat every
/// `Code::Unknown` as an unknown outcome, `unmapped_status_falls_back_to_internal` and
/// `unavailable_status_maps_to_disconnected` in `error.rs`'s own tests would still pass while
/// silently turning ordinary flaky-network noise into a non-retryable outcome for every mutation
/// in the fleet -- this is the boundary the contract's point 2 exists to hold.
#[test]
fn an_unmarked_grpc_unknown_status_is_still_disconnected_not_outcome_unknown() {
    let status = tonic::Status::unknown("peer reset the stream");
    let error = ProtocolError::from(status);

    assert!(
        error.is_disconnected(),
        "an unmarked Code::Unknown must fall back to the pre-existing Disconnected reading: \
         {error:?}"
    );
    assert!(
        !error.is_outcome_unknown(),
        "the unknown-outcome upgrade must never be inferred from a bare Unknown code alone: \
         {error:?}"
    );
}

/// A status marked as an unknown outcome, but missing the optional operation/attempt headers
/// (a peer that sets only the required key/value marker), must still decode as `OutcomeUnknown`
/// rather than being silently discarded -- `outcome_unknown_marker`'s own doc comment states this
/// explicitly ("dropping it because the identity is thin would turn it back into the retryable
/// error the whole contract exists to avoid").
#[test]
fn a_marker_with_no_companion_headers_still_decodes_as_outcome_unknown() {
    let mut status = tonic::Status::unknown("indeterminate");
    status.metadata_mut().insert(
        "lore-outcome-unknown",
        "v1".parse().expect("ascii metadata value"),
    );

    let error = ProtocolError::from(status);
    assert!(
        error.is_outcome_unknown(),
        "a bare marker with no operation/attempt headers must still be honoured: {error:?}"
    );
}

/// A marker value other than the one honoured version must not be read as the outcome-unknown
/// marker -- exactly the reason the module documents a versioned value rather than any non-empty
/// one: an old client and a hypothetical future marker version must not silently agree.
#[test]
fn an_unrecognised_marker_version_is_not_honoured() {
    let mut status = tonic::Status::unknown("some other server-side marker scheme");
    status.metadata_mut().insert(
        "lore-outcome-unknown",
        "v2".parse().expect("ascii metadata value"),
    );

    let error = ProtocolError::from(status);
    assert!(
        !error.is_outcome_unknown(),
        "an unrecognised marker version must not be honoured as v1: {error:?}"
    );
    assert!(error.is_disconnected());
}

/// Priority (a): an unknown outcome must never satisfy any OTHER predicate this error type
/// exposes -- not just "is not Disconnected" (the property the reconnect wrappers rely on
/// directly), but every retry-adjacent or fallback predicate a caller anywhere in the stack
/// might branch on. A caller that checks the wrong one and finds it true would silently treat an
/// unresolved mutation as something safe to retry, ignore, or paper over.
#[test]
fn an_unknown_outcome_satisfies_no_other_error_predicate() {
    let error = outcome_unknown("StorageService.MutableCompareAndSwap", &AttemptId::new());

    assert!(error.is_outcome_unknown());
    assert!(!error.is_disconnected());
    assert!(!error.is_slow_down());
    assert!(!error.is_not_authorized());
    assert!(!error.is_not_authenticated());
    assert!(!error.is_maintenance());
    assert!(!error.is_not_found());
    assert!(!error.is_no_remote());
    assert!(!error.is_not_supported());
    assert!(!error.is_oversized());
    assert!(!error.is_internal());
}

/// The capability constant is exactly what a downstream caller (e.g. WP-116's control-plane
/// adapter, or a desktop capability negotiation) is expected to declare -- pin the literal, not
/// just its presence, since a silent rename would break every caller that hard-codes the string
/// on the other side of a wire boundary this crate does not own.
#[test]
fn the_capability_literal_is_exactly_outcome_unknown_v1() {
    assert_eq!(OUTCOME_UNKNOWN_CAPABILITY_V1, "outcome_unknown_v1");
    assert!(supports_outcome_unknown_v1());
}
