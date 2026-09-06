// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// A server that refuses a bearer for a precise reason (e.g. "bearer audience
// commit0-storage is not the human authn audience") had that reason dropped by
// `lore-transport`'s gRPC status mapping: `lore_base::error::NotAuthenticated`
// was a unit struct with the fixed Display "Not authenticated", so the
// server's own text had nowhere to travel and the caller saw only three
// characterless words. `NotAuthenticated` gained a `reason: String` field,
// mirroring the existing sibling precedent `NotConnected { reason: String }`
// in the same file (`lore-base/src/error.rs`).
//
// [CLIENT]-class: `lore-transport` is a client-path crate; every gRPC client
// verb in this crate routes an `Unauthenticated` status through
// `ProtocolError::from(tonic::Status)`, so this mapping is felt everywhere,
// not just on one call site. FFI code 16, the C ABI, and `lore-capi/lore.h`
// are unchanged by this delta -- the reason reaches a C consumer through the
// existing `LoreErrorDetail.message` field (`error.to_string()`).

use lore_base::error::NotAuthenticated;
use lore_base::error::UNSTATED_REFUSAL;
use lore_error_set::FfiError;
use lore_transport::error::ProtocolError;
use tonic::Code;
use tonic::Status;

const AUDIENCE_REASON: &str = "bearer audience commit0-storage is not the human authn audience";
const MUTATION_REASON: &str = "Governed mutations require the human authentication bearer in the lore-authn-bearer metadata header";

// ---------------------------------------------------------------------------
// 1. A server-supplied refusal reason survives to the client error's Display.
// ---------------------------------------------------------------------------

#[test]
fn a_server_supplied_reason_survives_to_the_display_and_keeps_ffi_code_16() {
    let status = Status::unauthenticated(AUDIENCE_REASON);
    let err = ProtocolError::from(status);

    assert!(
        matches!(err, ProtocolError::NotAuthenticated(_)),
        "expected NotAuthenticated, got {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains(AUDIENCE_REASON),
        "expected the server's exact refusal text in the Display, got {rendered:?}"
    );
    assert_eq!(err.ffi_code(), 16);
}

// ---------------------------------------------------------------------------
// 2. A second, differently-worded reason also survives verbatim, and two
//    distinct reasons produce two distinct Display strings.
// ---------------------------------------------------------------------------

#[test]
fn a_second_distinct_reason_also_survives_verbatim_and_differs_from_the_first() {
    let first = ProtocolError::from(Status::unauthenticated(AUDIENCE_REASON)).to_string();
    let second = ProtocolError::from(Status::unauthenticated(MUTATION_REASON)).to_string();

    assert!(
        first.contains(AUDIENCE_REASON),
        "first Display lost the server's text: {first:?}"
    );
    assert!(
        second.contains(MUTATION_REASON),
        "second Display lost the server's text: {second:?}"
    );
    assert_ne!(
        first, second,
        "two distinct server reasons must not collapse to the same fixed Display string -- \
         this is what proves the text is carried rather than a new fixed string"
    );
}

// ---------------------------------------------------------------------------
// 3. An empty server message still yields a sane Display.
// ---------------------------------------------------------------------------

#[test]
fn an_empty_server_message_falls_back_to_the_unstated_refusal_constant() {
    let status = Status::unauthenticated("");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::NotAuthenticated(_)));

    let rendered = err.to_string();
    assert!(!rendered.is_empty(), "Display must never be empty");
    assert!(
        rendered.starts_with("Not authenticated"),
        "expected the Display to start with \"Not authenticated\", got {rendered:?}"
    );
    assert!(
        rendered.contains(UNSTATED_REFUSAL),
        "expected the public UNSTATED_REFUSAL constant text in the Display, got {rendered:?}"
    );
    assert!(
        !rendered.ends_with(": "),
        "Display must never be a dangling \"Not authenticated: \", got {rendered:?}"
    );
    assert!(
        !rendered.trim_end().ends_with(':'),
        "Display must never end in a bare colon, got {rendered:?}"
    );
}

/// The production check is `message.trim().is_empty()`, not `message.is_empty()`, so a
/// whitespace-only message is a distinct branch from a literally-empty one: a test that only
/// tries `""` would still pass against a narrower `message.is_empty()` implementation that left
/// a whitespace-only reason to render as `"Not authenticated:    "`.
#[test]
fn a_whitespace_only_server_message_also_falls_back_to_the_unstated_refusal_constant() {
    let status = Status::unauthenticated("   \t  ");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::NotAuthenticated(_)));

    let rendered = err.to_string();
    assert_eq!(
        rendered,
        format!("Not authenticated: {UNSTATED_REFUSAL}"),
        "a whitespace-only reason must be treated the same as an empty one, got {rendered:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Regression pins: neighbouring arms in the same match are untouched.
// ---------------------------------------------------------------------------

#[test]
fn unavailable_status_still_maps_to_disconnected() {
    let err = ProtocolError::from(Status::unavailable("server unreachable"));
    assert!(matches!(err, ProtocolError::Disconnected(_)));
    assert_eq!(err.ffi_code(), 28);
}

#[test]
fn internal_status_still_maps_to_internal() {
    let err = ProtocolError::from(Status::internal("something went wrong"));
    assert!(matches!(err, ProtocolError::Internal(_)));
    assert_eq!(err.ffi_code(), -1);
}

#[test]
fn permission_denied_status_still_maps_to_not_authorized() {
    let err = ProtocolError::from(Status::permission_denied("no access"));
    assert!(matches!(err, ProtocolError::NotAuthorized(_)));
}

// ---------------------------------------------------------------------------
// 5. Round trip: ProtocolError -> tonic::Status carries the reason back out.
// ---------------------------------------------------------------------------

#[test]
fn round_trip_through_tonic_status_carries_the_reason() {
    let original = ProtocolError::from(NotAuthenticated::new("some reason"));
    let status = Status::from(original);

    assert_eq!(status.code(), Code::Unauthenticated);
    assert!(
        status.message().contains("some reason"),
        "expected the reason to survive the round trip into a tonic::Status, got {:?}",
        status.message()
    );
}

// ---------------------------------------------------------------------------
// 6. FFI code stability through a forward into a sibling error-set enum.
// ---------------------------------------------------------------------------
//
// `lore_transport::auth::exchange::ExchangeError` is a second, independently
// declared `#[error_set]` enum reachable from this crate's public API that
// also declares `NotAuthenticated`. Forwarding a `ProtocolError` into it
// (the same `.forward::<Target>(..)` seam production call sites use, e.g.
// `connection.rs`'s `.forward::<ProtocolError>(..)`) must preserve both the
// FFI code and the carried reason text -- the reason lives on the wrapped
// `lore_base::error::NotAuthenticated` value itself, not on the enum that
// happens to be carrying it.

#[test]
fn forwarding_into_a_sibling_error_set_keeps_ffi_code_16_and_the_reason() {
    use lore_transport::auth::exchange::ExchangeError;

    let protocol_err = ProtocolError::from(Status::unauthenticated(AUDIENCE_REASON));
    assert!(matches!(protocol_err, ProtocolError::NotAuthenticated(_)));

    let forwarded: ExchangeError = protocol_err.forward("unauthenticated_reason test forward");

    assert!(
        matches!(forwarded, ExchangeError::NotAuthenticated(_)),
        "expected the forward to land in ExchangeError::NotAuthenticated, got {forwarded:?}"
    );
    assert_eq!(forwarded.ffi_code(), 16);
    let rendered = forwarded.to_string();
    assert!(
        rendered.contains(AUDIENCE_REASON),
        "expected the reason to survive the forward into ExchangeError, got {rendered:?}"
    );
}
