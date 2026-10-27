// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use lore_error_set::prelude::*;
use lore_transport::error::*;

// CR-017(c): a server-side auth rejection must classify as `NotAuthenticated`
// (FFI 16), not collapse into the catch-all `Internal` (FFI -1) — a client
// needs to distinguish "not authenticated" from an opaque internal error to
// drive recovery (WP-074 Phase 1).
#[test]
fn unauthenticated_status_maps_to_not_authenticated() {
    let status = tonic::Status::unauthenticated("authorization header required");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::NotAuthenticated(_)));
    // Codes are `#[ffi_code(..)]` in `lore-base/src/error.rs`; upstream
    // b98b4d6 regrouped them into blocks, which is what a mismatch means.
    assert_eq!(err.ffi_code(), 16);
}

// Regression pin: a neighboring arm untouched by CR-017(c) still classifies
// correctly.
#[test]
fn unavailable_status_maps_to_disconnected() {
    let status = tonic::Status::unavailable("server unreachable");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::Disconnected(_)));
    assert_eq!(err.ffi_code(), 28);
}

// An unmapped tonic code still falls through to `Internal`, not
// `NotAuthenticated` or any other handleable variant.
#[test]
fn unmapped_status_falls_back_to_internal() {
    let status = tonic::Status::internal("something went wrong");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::Internal(_)));
    assert_eq!(err.ffi_code(), -1);
}

// --- ResourceExhausted from an h2 ENHANCE_YOUR_CALM failure (the sourceless control is
// `ordinary_resource_exhausted_backpressure_maps_to_slow_down_and_does_not_mark`) ---

/// `tonic` derives `ResourceExhausted` from an h2 error whose reason is `ENHANCE_YOUR_CALM`
/// (the client's own `too_many_internal_resets` GOAWAY, or a peer's reset) and attaches that
/// error as the source. It is a lost answer, never `SlowDown`, which callers retry.
#[test]
fn enhance_your_calm_resource_exhausted_is_a_lost_answer() {
    let status =
        tonic::Status::from_error(Box::new(h2::Error::from(h2::Reason::ENHANCE_YOUR_CALM)));
    assert_eq!(
        status.code(),
        tonic::Code::ResourceExhausted,
        "sanity: tonic maps ENHANCE_YOUR_CALM to ResourceExhausted"
    );
    assert!(
        std::error::Error::source(&status).is_some(),
        "sanity: tonic attaches the h2 error as the source"
    );
    let err = ProtocolError::from(status);
    assert!(!err.is_slow_down(), "{err:?}");
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::ResourceExhausted));

    // A relaying peer re-emits the code with the answer-lost header, and it re-marks.
    let relayed: tonic::Status = err.into();
    assert_eq!(relayed.code(), tonic::Code::ResourceExhausted);
    let reconverted = ProtocolError::from(relayed);
    assert!(!reconverted.is_slow_down(), "{reconverted:?}");
    assert_eq!(
        answer_lost_code(&reconverted),
        Some(tonic::Code::ResourceExhausted)
    );
}

// --- Cancelled/DeadlineExceeded/sourced-Internal answer-lost split (the fix under test) ---
//
// Neither code is ever raised by a lock handler as a refusal
// (`lore-server/src/grpc/lock_service.rs`'s `handle_lock_error` refuses with `NotFound`,
// `FailedPrecondition`, `ResourceExhausted`, `InvalidArgument`, or `Internal`), so both must
// carry the `AnswerLostInTransit` marker and read as `answer_lost_code == Some(_)` rather
// than a decisive refusal.

#[test]
fn cancelled_status_marks_answer_lost_with_cancelled_code() {
    let status = tonic::Status::cancelled("mid-flight stream reset");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::Internal(_)));
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::Cancelled));
    assert!(
        err.to_string().contains("mid-flight stream reset"),
        "the status's own message must survive the collapse into Internal: {err}"
    );
}

#[test]
fn deadline_exceeded_status_marks_answer_lost_with_deadline_exceeded_code() {
    let status = tonic::Status::deadline_exceeded("grpc-timeout expired");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::Internal(_)));
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::DeadlineExceeded));
    assert!(
        err.to_string().contains("grpc-timeout expired"),
        "the status's own message must survive the collapse into Internal: {err}"
    );
}

// Negative control, load-bearing: a server-shaped `Internal` (built with `Status::new`, no
// source -- exactly what `handle_lock_error` produces) is a genuine decisive refusal and must
// NOT carry the answer-lost marker. Without this case, a broken fix that funnelled every
// `Internal` into `AnswerLostInTransit` would still pass every other case here -- this is
// what proves the split is real rather than "everything is now unknown".
#[test]
fn server_shaped_internal_status_has_no_answer_lost_marker() {
    let status = tonic::Status::internal("refused: resource locked by another owner");
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: Status::internal must be sourceless for this negative control to mean \
         anything"
    );
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::Internal(_)));
    assert_eq!(answer_lost_code(&err), None);
    assert!(
        err.to_string()
            .contains("refused: resource locked by another owner"),
        "the refusal's own message must survive into the error: {err}"
    );
}

/// A minimal error wrapper whose only job is to expose a `tonic::Status` as its `source()`,
/// so `tonic::Status::from_error` can be driven the same way its own `from_h2_error` drives
/// it internally: `try_from_error` walks the source chain, finds the embedded `Status`, and
/// builds a NEW status carrying that inner status's code plus the ORIGINAL wrapper as its own
/// source -- which is exactly the "transport failed the call, and the failure carries a
/// source" shape `error.rs`'s `Internal if source().is_some()` arm exists for.
#[derive(Debug)]
struct WrapsStatus(tonic::Status);

impl std::fmt::Display for WrapsStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wrapped: {}", self.0)
    }
}

impl std::error::Error for WrapsStatus {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[test]
fn sourced_internal_status_marks_answer_lost_with_internal_code() {
    let inner = tonic::Status::internal("h2 protocol error: stream reset by peer");
    let wrapped = WrapsStatus(inner);
    let transport_status = tonic::Status::from_error(Box::new(wrapped));

    // Sanity checks on the construction itself, run first so a failure here is legible
    // rather than surfacing as a confusing assertion failure two lines down.
    assert_eq!(
        transport_status.code(),
        tonic::Code::Internal,
        "sanity: Status::from_error must preserve the wrapped status's code"
    );
    assert!(
        std::error::Error::source(&transport_status).is_some(),
        "sanity: Status::from_error must attach a source for this case to mean anything -- \
         if this ever fails, tonic's construction changed and this test's method for \
         producing a sourced Internal no longer works"
    );

    let err = ProtocolError::from(transport_status);
    assert!(matches!(err, ProtocolError::Internal(_)));
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::Internal));
}

// --- Round-trip: `From<ProtocolError> for tonic::Status`'s marker-preserving early return ---
//
// A relaying server converts a client-observed `ProtocolError` back into a `tonic::Status` to
// answer its own caller. Before the early return existed, a marked `Cancelled` came back out
// as a plain `Code::Internal` with no marker, so the ambiguity died at the first relay hop
// instead of reaching the caller who actually needs to decide whether to reconcile.

#[test]
fn cancelled_status_round_trips_and_remarks_on_reconversion() {
    let original = tonic::Status::cancelled("mid-flight stream reset");
    let err = ProtocolError::from(original);
    let round_tripped: tonic::Status = err.into();
    assert_eq!(
        round_tripped.code(),
        tonic::Code::Cancelled,
        "a relaying server must re-emit the funnelled code, not flatten it to Internal"
    );

    let reconverted = ProtocolError::from(round_tripped);
    assert_eq!(
        answer_lost_code(&reconverted),
        Some(tonic::Code::Cancelled),
        "the marker must survive a second hop, not just the first -- Cancelled/\
         DeadlineExceeded mark unconditionally on code alone, with no source requirement, so \
         a round-tripped (necessarily sourceless) status still re-marks"
    );
}

#[test]
fn deadline_exceeded_status_round_trips_and_remarks_on_reconversion() {
    let original = tonic::Status::deadline_exceeded("grpc-timeout expired");
    let err = ProtocolError::from(original);
    let round_tripped: tonic::Status = err.into();
    assert_eq!(
        round_tripped.code(),
        tonic::Code::DeadlineExceeded,
        "a relaying server must re-emit the funnelled code, not flatten it to Internal"
    );

    let reconverted = ProtocolError::from(round_tripped);
    assert_eq!(
        answer_lost_code(&reconverted),
        Some(tonic::Code::DeadlineExceeded),
        "the marker must survive a second hop, not just the first"
    );
}

/// A sourced `Internal`'s marker now survives every hop, not just the first -- closed by the
/// `ANSWER_LOST_METADATA_KEY` header, which `From<ProtocolError> for tonic::Status` stamps
/// whenever `answer_lost_code` is `Some(_)`, independent of whether the outgoing status
/// happens to carry a source. `From<ProtocolError> for tonic::Status`'s early return still
/// always builds the outgoing status with `tonic::Status::new(code, msg)`, and
/// `tonic::Status::new` always leaves `source: None` -- so a round-tripped sourced-`Internal`
/// still loses the source property the `Internal` arm's own source test would need to
/// re-mark it. What changed is that the metadata marker no longer depends on that arm at all:
/// it is read unconditionally, before the code match, so sourcelessness stops mattering.
///
/// This test replaces
/// `sourced_internal_status_round_trips_to_internal_code_but_the_marker_does_not_survive_a_second_hop`,
/// which pinned the pre-fix one-hop gap; per that test's own comment, a flip to `Some(_)`
/// here is a real close of the gap, and this rename plus flipped expectation is that close.
#[test]
fn sourced_internal_status_marker_survives_every_hop() {
    let inner = tonic::Status::internal("h2 protocol error: stream reset by peer");
    let transport_status = tonic::Status::from_error(Box::new(WrapsStatus(inner)));
    let err = ProtocolError::from(transport_status);
    assert_eq!(
        answer_lost_code(&err),
        Some(tonic::Code::Internal),
        "sanity: the first conversion must mark, matching \
         sourced_internal_status_marks_answer_lost_with_internal_code above"
    );

    let round_tripped: tonic::Status = err.into();
    assert_eq!(
        round_tripped.code(),
        tonic::Code::Internal,
        "the wire code itself must still be Internal after the round trip"
    );
    assert!(
        std::error::Error::source(&round_tripped).is_none(),
        "sanity: this is precisely why the metadata marker carries the fact -- the outgoing \
         status built by the early return is always sourceless, so the Internal arm's own \
         source test could never re-mark this on its own"
    );

    let reconverted = ProtocolError::from(round_tripped);
    assert_eq!(
        answer_lost_code(&reconverted),
        Some(tonic::Code::Internal),
        "the metadata marker must survive the second hop even though the source does not"
    );

    // A third hop, since the claim is "every hop", not "two hops".
    let round_tripped_again: tonic::Status = reconverted.into();
    assert_eq!(round_tripped_again.code(), tonic::Code::Internal);
    let reconverted_again = ProtocolError::from(round_tripped_again);
    assert_eq!(
        answer_lost_code(&reconverted_again),
        Some(tonic::Code::Internal),
        "the marker must survive a third hop too"
    );
}

// --- Negative controls: the new early return must not capture an unmarked error ---

#[test]
fn server_shaped_internal_status_round_trips_to_internal_with_no_marker() {
    let original = tonic::Status::internal("refused: resource locked by another owner");
    let err = ProtocolError::from(original);
    assert_eq!(
        answer_lost_code(&err),
        None,
        "sanity: no marker on the way in"
    );

    let round_tripped: tonic::Status = err.into();
    assert_eq!(
        round_tripped.code(),
        tonic::Code::Internal,
        "the new early return in `From<ProtocolError> for tonic::Status` must not capture an \
         unmarked Internal -- only answer_lost_code(&value).is_some() takes that branch, so \
         this must fall through to the ordinary ProtocolError::Internal(_) arm"
    );
    assert!(
        round_tripped
            .metadata()
            .get(ANSWER_LOST_METADATA_KEY)
            .is_none(),
        "an unmarked Internal must not acquire the lore-answer-lost header on its way out"
    );

    let reconverted = ProtocolError::from(round_tripped);
    assert_eq!(
        answer_lost_code(&reconverted),
        None,
        "an unmarked refusal must never acquire a marker across a round trip"
    );
}

#[test]
fn protocol_error_internal_built_directly_has_no_marker_and_maps_to_internal_code() {
    let err = ProtocolError::internal("built directly, no status involved");
    assert_eq!(
        answer_lost_code(&err),
        None,
        "an error built via ProtocolError::internal (never touched a tonic::Status at all) \
         must never spuriously carry the answer-lost marker"
    );

    let status: tonic::Status = err.into();
    assert_eq!(
        status.code(),
        tonic::Code::Internal,
        "the new early return must not fire for an error with no marker, so this must still \
         take the plain ProtocolError::Internal(_) arm"
    );
}

// --- Positive: `tonic`'s own sourceless response-decode messages now mark ---
//
// `tonic` raises these as a sourceless `Status::internal(...)` for a response that ends or
// fails to decode without ever producing a real verdict -- confirmed against tonic 0.14.6:
// `client/grpc.rs:253` ("Missing response message."), `codec/decode.rs:273` ("Unexpected EOF
// decoding stream."), and `codec/decode.rs:168` (the compressed-flag-without-encoding
// protocol error). Each carries no source to key off of, so the source test alone cannot
// reach them; `is_tonic_lost_response` closes exactly this residual by matching `tonic`'s own
// message text. This test replaces
// `known_gap_sourceless_stream_truncation_internal_statuses_read_as_decisive`, which pinned
// the pre-fix gap and said explicitly that a flip to `Some(_)` here is a real close of the
// gap, not a break -- this rename and flipped expectation is that close.
#[test]
fn sourceless_tonic_response_receive_messages_mark_answer_lost() {
    for message in [
        "Missing response message.",
        "Unexpected EOF decoding stream.",
        "protocol error: received message with compressed-flag but no grpc-encoding was specified",
    ] {
        let status = tonic::Status::internal(message);
        assert!(
            std::error::Error::source(&status).is_none(),
            "sanity: {message:?} is sourceless when tonic raises it, which is exactly what \
             is_tonic_lost_response must recognise without a source to key off of"
        );
        let err = ProtocolError::from(status);
        assert_eq!(
            answer_lost_code(&err),
            Some(tonic::Code::Internal),
            "{message:?} is one of tonic's own lost-response messages and must mark as \
             answer-lost rather than read as a decisive Internal"
        );
        assert!(
            err.to_string().contains(message),
            "the diagnostic must not be lost in the collapse: {err}"
        );
    }
}

/// Reproduces `tonic` 0.14.6's `codec/decode.rs:174-186` `Direction::Response` arm verbatim
/// (not paraphrased), so this proves the crate's prefix-plus-substring match actually matches
/// what `tonic` writes rather than an approximation of it. `{status}` there is an
/// `http::StatusCode`, not a `tonic::Status` -- see `Direction::Response(StatusCode)`.
#[test]
fn invalid_compression_flag_response_rendering_marks_answer_lost() {
    let f: u8 = 3;
    let status_code = http::StatusCode::OK;
    let message = format!(
        "protocol error: received message with invalid compression flag: {f} (valid flags are 0 and 1) while receiving response with status: {status_code}"
    );
    let status = tonic::Status::internal(message);
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless, matching how tonic raises this"
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::Internal));
}

/// Reproduces `tonic` 0.14.6's `codec/decode.rs:235-238` `Direction::Response` arm verbatim.
#[test]
fn decompression_failed_response_rendering_marks_answer_lost() {
    let err_display = "invalid gzip header";
    let status_code = http::StatusCode::OK;
    let message = format!(
        "Error decompressing: {err_display}, while receiving response with status: {status_code}"
    );
    let status = tonic::Status::internal(message);
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless, matching how tonic raises this"
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::Internal));
}

// --- Negative controls: decisive text that must not be conflated with the matched shapes ---
//
// The load-bearing half: an implementation that marked every `Internal` would still pass
// every positive case above, so these prove the split is real.

/// `server/grpc.rs:386`'s sibling to `client/grpc.rs:253`'s "Missing response message." --
/// this one is the SERVER's own words for never having decoded our request, which is
/// decisive: the handler never ran. Differs from the matched string by one word, which is
/// exactly the boundary the exact-string match must respect.
#[test]
fn missing_request_message_does_not_mark_answer_lost() {
    let status = tonic::Status::internal("Missing request message.");
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless"
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), None);
}

/// The REQUEST-direction rendering of the same interpolated site as
/// `invalid_compression_flag_response_rendering_marks_answer_lost` -- decisive, because it
/// means a server could not decode what THIS client sent, not that this client lost a
/// response.
#[test]
fn invalid_compression_flag_request_rendering_does_not_mark_answer_lost() {
    let f: u8 = 3;
    let message = format!(
        "protocol error: received message with invalid compression flag: {f} (valid flags are 0 and 1), while sending request"
    );
    let status = tonic::Status::internal(message);
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless"
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), None);
}

/// The REQUEST-direction rendering of the decompression-failure site.
#[test]
fn decompression_failed_request_rendering_does_not_mark_answer_lost() {
    let err_display = "invalid gzip header";
    let message = format!("Error decompressing: {err_display}, while sending request");
    let status = tonic::Status::internal(message);
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless"
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), None);
}

/// `codec/encode.rs`'s send-side errors -- decisive, this client's own encoder/compressor
/// failed before anything went on the wire.
#[test]
fn encode_and_compress_errors_do_not_mark_answer_lost() {
    for message in ["Error encoding: whatever", "Error compressing: whatever"] {
        let status = tonic::Status::internal(message);
        assert!(
            std::error::Error::source(&status).is_none(),
            "sanity: {message:?} is sourceless"
        );
        let err = ProtocolError::from(status);
        assert_eq!(answer_lost_code(&err), None, "{message:?} must not mark");
    }
}

/// Proves the exact-string matches in `is_tonic_lost_response` are exact, not `contains`: a
/// message that merely CONTAINS one of the matched strings, or differs from it only in case
/// or trailing punctuation, must read as a decisive refusal.
#[test]
fn near_miss_variants_of_the_exact_matched_strings_do_not_mark_answer_lost() {
    for message in [
        "refused: Unexpected EOF decoding stream. during handler validation",
        "unexpected eof decoding stream.",
        "Unexpected EOF decoding stream!",
    ] {
        let status = tonic::Status::internal(message);
        assert!(
            std::error::Error::source(&status).is_none(),
            "sanity: {message:?} is sourceless"
        );
        let err = ProtocolError::from(status);
        assert_eq!(
            answer_lost_code(&err),
            None,
            "{message:?} is not an exact match for a tonic-raised lost-response message"
        );
    }
}

// --- Relay-hop coverage ---

#[test]
fn cancelled_status_survives_two_relay_hops() {
    let original = tonic::Status::cancelled("mid-flight stream reset");
    let err = ProtocolError::from(original);
    let round_tripped: tonic::Status = err.into();
    let reconverted = ProtocolError::from(round_tripped);
    assert_eq!(
        answer_lost_code(&reconverted),
        Some(tonic::Code::Cancelled),
        "sanity: the first hop must still mark"
    );

    let round_tripped_again: tonic::Status = reconverted.into();
    assert_eq!(round_tripped_again.code(), tonic::Code::Cancelled);
    let reconverted_again = ProtocolError::from(round_tripped_again);
    assert_eq!(
        answer_lost_code(&reconverted_again),
        Some(tonic::Code::Cancelled),
        "the marker must survive a second relay hop, not just the first"
    );
}

#[test]
fn deadline_exceeded_status_survives_two_relay_hops() {
    let original = tonic::Status::deadline_exceeded("grpc-timeout expired");
    let err = ProtocolError::from(original);
    let round_tripped: tonic::Status = err.into();
    let reconverted = ProtocolError::from(round_tripped);
    assert_eq!(
        answer_lost_code(&reconverted),
        Some(tonic::Code::DeadlineExceeded),
        "sanity: the first hop must still mark"
    );

    let round_tripped_again: tonic::Status = reconverted.into();
    assert_eq!(round_tripped_again.code(), tonic::Code::DeadlineExceeded);
    let reconverted_again = ProtocolError::from(round_tripped_again);
    assert_eq!(
        answer_lost_code(&reconverted_again),
        Some(tonic::Code::DeadlineExceeded),
        "the marker must survive a second relay hop, not just the first"
    );
}

/// A text-matched lost response (`is_tonic_lost_response`, not a code-only or sourced arm)
/// round-trips through a relay hop and keeps marking, proving the outbound stamp is keyed on
/// `answer_lost_code` rather than on which arm produced it. Also the diagnostic-survival pin
/// for this family: the original message must still be readable after the collapse.
#[test]
fn text_matched_lost_response_round_trips_and_carries_the_metadata_marker() {
    let status = tonic::Status::internal("Unexpected EOF decoding stream.");
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::Internal));

    let round_tripped: tonic::Status = err.into();
    assert_eq!(round_tripped.code(), tonic::Code::Internal);
    assert_eq!(
        round_tripped
            .metadata()
            .get(ANSWER_LOST_METADATA_KEY)
            .and_then(|value| value.to_str().ok()),
        Some(ANSWER_LOST_METADATA_VALUE),
        "the outgoing status must carry the lore-answer-lost marker"
    );
    assert!(
        round_tripped
            .message()
            .contains("Unexpected EOF decoding stream."),
        "the diagnostic must not be lost in the collapse: {round_tripped}"
    );

    let reconverted = ProtocolError::from(round_tripped);
    assert_eq!(answer_lost_code(&reconverted), Some(tonic::Code::Internal));
}

/// Proves the outbound `lore-answer-lost` stamp is gated on `answer_lost_code`, not applied
/// to every outgoing status: three codes with no answer-lost arm at all must never carry it.
#[test]
fn unauthenticated_not_found_and_slow_down_round_trips_never_acquire_the_answer_lost_header() {
    let cases = [
        tonic::Status::unauthenticated("authorization header required"),
        tonic::Status::not_found("no such repository"),
        tonic::Status::resource_exhausted("try again later"),
    ];
    for original in cases {
        let err = ProtocolError::from(original);
        assert_eq!(
            answer_lost_code(&err),
            None,
            "sanity: no marker on the way in"
        );
        let round_tripped: tonic::Status = err.into();
        assert!(
            round_tripped
                .metadata()
                .get(ANSWER_LOST_METADATA_KEY)
                .is_none(),
            "must never acquire the lore-answer-lost header: {round_tripped:?}"
        );
    }
}

/// A status carrying both markers resolves to the stronger, more specific
/// `ProtocolError::OutcomeUnknown` -- the server identified its own ambiguity, which outranks
/// this client's inference from a re-emitted answer-lost header. The outcome-unknown check
/// runs first in `From<tonic::Status> for ProtocolError` on purpose; this pins that ordering.
#[test]
fn a_status_carrying_both_markers_resolves_to_outcome_unknown_not_answer_lost() {
    let mut status = tonic::Status::internal("ambiguous");
    {
        let metadata = status.metadata_mut();
        insert_marker(
            metadata,
            lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
            lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_VALUE,
        );
        insert_marker(
            metadata,
            ANSWER_LOST_METADATA_KEY,
            ANSWER_LOST_METADATA_VALUE,
        );
    }

    let err = ProtocolError::from(status);
    assert!(
        matches!(err, ProtocolError::OutcomeUnknown(_)),
        "the outcome-unknown marker must win over the weaker answer-lost marker: {err:?}"
    );
}

// --- OutOfRange / ResourceExhausted lost-response shapes (round #2) ---
//
// `is_tonic_lost_response` moved out of the `Internal` arm and gained these two shapes.
// `ResourceExhausted` was the sharp bug: `SlowDown` is the one code `handle_error` retries,
// so a `MutableNoReplay` mutation whose response was too big to decompress was genuinely
// reissued rather than merely misreported.

#[test]
fn message_too_large_response_rendering_marks_answer_lost_with_out_of_range_code() {
    // Reproduces tonic 0.14.6's codec/decode.rs:194-196 verbatim -- unlike the
    // compression-flag/decompression sites, this one is not direction-dependent.
    let len: usize = 999_999;
    let limit: usize = 4 * 1024 * 1024;
    let message = format!(
        "Error, decoded message length too large: found {len} bytes, the limit is: {limit} bytes"
    );
    let status = tonic::Status::out_of_range(message);
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless, matching how tonic raises this"
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::OutOfRange));
}

#[test]
fn decompress_size_limit_response_rendering_marks_answer_lost_with_resource_exhausted_code() {
    // Reproduces tonic 0.14.6's codec/decode.rs:231-233 verbatim -- also not
    // direction-dependent.
    let limit: usize = 4 * 1024 * 1024;
    let message = format!(
        "Error decompressing: size limit, of {limit} bytes, exceeded while decompressing message"
    );
    let status = tonic::Status::resource_exhausted(message);
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless, matching how tonic raises this"
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), Some(tonic::Code::ResourceExhausted));
}

#[test]
fn out_of_range_and_resource_exhausted_lost_responses_survive_a_relay_hop() {
    let limit: usize = 4 * 1024 * 1024;
    let cases = [
        (
            format!(
                "Error, decoded message length too large: found 999999 bytes, the limit is: {limit} bytes"
            ),
            tonic::Code::OutOfRange,
        ),
        (
            format!(
                "Error decompressing: size limit, of {limit} bytes, exceeded while decompressing message"
            ),
            tonic::Code::ResourceExhausted,
        ),
    ];
    for (message, code) in cases {
        let status = tonic::Status::new(code, message);
        let err = ProtocolError::from(status);
        assert_eq!(
            answer_lost_code(&err),
            Some(code),
            "sanity: must mark before the round trip"
        );

        let round_tripped: tonic::Status = err.into();
        assert_eq!(
            round_tripped.code(),
            code,
            "the outgoing status must keep its own code, not flatten to Internal"
        );
        assert_eq!(
            round_tripped
                .metadata()
                .get(ANSWER_LOST_METADATA_KEY)
                .and_then(|value| value.to_str().ok()),
            Some(ANSWER_LOST_METADATA_VALUE),
            "the outgoing status must carry the lore-answer-lost marker for {code:?}"
        );

        let reconverted = ProtocolError::from(round_tripped);
        assert_eq!(
            answer_lost_code(&reconverted),
            Some(code),
            "the marker must survive reconversion for {code:?}"
        );
    }
}

// --- Negative controls: the load-bearing half for round #2 ---

#[test]
fn ordinary_resource_exhausted_backpressure_maps_to_slow_down_and_does_not_mark() {
    let status = tonic::Status::resource_exhausted("too many concurrent lock requests");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::SlowDown(_)));
    assert_eq!(
        answer_lost_code(&err),
        None,
        "an ordinary server backpressure refusal must not be swallowed into answer-lost -- \
         this is the regression pin for the bug that used to let handle_error reissue a \
         MutableNoReplay mutation"
    );
}

#[test]
fn ordinary_out_of_range_refusal_maps_to_oversized_and_does_not_mark() {
    let status = tonic::Status::out_of_range("payload exceeds the configured maximum");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::Oversized(_)));
    assert_eq!(answer_lost_code(&err), None);
}

/// The suffix ("exceeded while decompressing message") is absent, so this must fall through
/// to the ordinary `ResourceExhausted` arm rather than being swallowed as answer-lost -- the
/// near-miss control for the sharper of the two new shapes.
#[test]
fn decompress_size_limit_near_miss_with_no_suffix_maps_to_slow_down_and_does_not_mark() {
    let status = tonic::Status::resource_exhausted("Error decompressing: size limit, of 5 bytes");
    let err = ProtocolError::from(status);
    assert!(matches!(err, ProtocolError::SlowDown(_)));
    assert_eq!(answer_lost_code(&err), None);
}

// --- Header gating: `is_answer_lost_code` bounds which codes honour the header ---

#[test]
fn unauthenticated_ignores_the_answer_lost_header_and_keeps_its_reason() {
    let mut status = tonic::Status::unauthenticated("authorization header required");
    insert_marker(
        status.metadata_mut(),
        ANSWER_LOST_METADATA_KEY,
        ANSWER_LOST_METADATA_VALUE,
    );
    let err = ProtocolError::from(status);
    assert_eq!(
        answer_lost_code(&err),
        None,
        "Unauthenticated is not in is_answer_lost_code's allowlist"
    );
    assert!(matches!(err, ProtocolError::NotAuthenticated(_)));
    assert!(
        err.to_string().contains("authorization header required"),
        "the refusal reason must survive, not collapse into a marked Internal: {err}"
    );
}

#[test]
fn not_found_ignores_the_answer_lost_header() {
    let mut status = tonic::Status::not_found("no such repository");
    insert_marker(
        status.metadata_mut(),
        ANSWER_LOST_METADATA_KEY,
        ANSWER_LOST_METADATA_VALUE,
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), None);
    assert!(matches!(err, ProtocolError::NotFound(_)));
}

#[test]
fn permission_denied_ignores_the_answer_lost_header() {
    let mut status = tonic::Status::permission_denied("write access required");
    insert_marker(
        status.metadata_mut(),
        ANSWER_LOST_METADATA_KEY,
        ANSWER_LOST_METADATA_VALUE,
    );
    let err = ProtocolError::from(status);
    assert_eq!(answer_lost_code(&err), None);
    assert!(matches!(err, ProtocolError::NotAuthorized(_)));
}

#[test]
fn a_wrong_header_value_does_not_mark_even_on_an_allowlisted_code() {
    let mut status = tonic::Status::internal("h2 protocol error: stream reset by peer");
    insert_marker(status.metadata_mut(), ANSWER_LOST_METADATA_KEY, "v2");
    assert!(
        std::error::Error::source(&status).is_none(),
        "sanity: sourceless, so no other arm can mark this either"
    );
    let err = ProtocolError::from(status);
    assert_eq!(
        answer_lost_code(&err),
        None,
        "an unrecognised marker version must not be honoured, even on an otherwise- \
         allowlisted code"
    );
}

/// The header alone must still mark when the code is allowlisted -- proven with `OutOfRange`
/// carrying an ORDINARY refusal message (not one of `is_tonic_lost_response`'s matched
/// shapes), so only the header path can be responsible for the mark. `Cancelled`/
/// `DeadlineExceeded` would mark unconditionally via their own code arm regardless of the
/// header, so they cannot isolate this path the way `OutOfRange` can.
#[test]
fn the_answer_lost_header_alone_marks_an_allowlisted_code_with_no_other_reason_to_mark() {
    let mut status = tonic::Status::out_of_range("payload exceeds the configured maximum");
    insert_marker(
        status.metadata_mut(),
        ANSWER_LOST_METADATA_KEY,
        ANSWER_LOST_METADATA_VALUE,
    );
    let err = ProtocolError::from(status);
    assert_eq!(
        answer_lost_code(&err),
        Some(tonic::Code::OutOfRange),
        "OutOfRange is in is_answer_lost_code's allowlist, so a correctly-versioned header \
         alone must mark it -- the gate must not be over-broad in the other direction either"
    );
}

// --- Not-prepared proof (`lore-not-prepared-attempt-v1`, Gate 0 campaign c13) ---
//
// A fenced cell that refuses before it files a receipt stamps this header with the request's
// attempt id. At the status-conversion layer the proof turns an otherwise lost-answer code into a
// decisive `Internal`; what settles an attempt is `with_reconnect_classified`, covered by
// `grpc/not_prepared_proof_wire_tests.rs`. `NOT_PREPARED_ATTEMPT_METADATA_KEY` is a public const.

fn status_with_markers(code: tonic::Code, values: &[&str]) -> tonic::Status {
    let mut status = tonic::Status::new(code, "verifier unavailable");
    for value in values {
        status.metadata_mut().append(
            lore_transport::outcome::NOT_PREPARED_ATTEMPT_METADATA_KEY,
            value.parse().expect("ascii metadata value"),
        );
    }
    status
}

/// Whether `err` is the decisive, proof-carrying shape: not a lost answer in any form.
fn is_refused_before_prepare(err: &ProtocolError) -> bool {
    matches!(err, ProtocolError::Internal(_))
        && answer_lost_code(err).is_none()
        && !err.is_outcome_unknown()
}

#[test]
fn a_well_formed_marker_turns_every_unsettled_code_into_a_decisive_refusal() {
    let attempt = uuid::Uuid::now_v7().to_string();
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::Unknown,
        tonic::Code::Cancelled,
        tonic::Code::DeadlineExceeded,
    ] {
        let err = ProtocolError::from(status_with_markers(code, &[&attempt]));
        assert!(
            is_refused_before_prepare(&err),
            "{code:?} carrying the proof must be a decisive Internal, got {err:?}"
        );
        assert!(
            !matches!(err, ProtocolError::Disconnected(_)),
            "{code:?} carrying the proof must not read as a lost channel"
        );
        assert!(
            err.to_string().contains("verifier unavailable"),
            "the status's own message must survive: {err}"
        );
    }
}

// Negative control for the test above: the same codes with no marker keep their old reading.
#[test]
fn an_unmarked_unsettled_code_keeps_its_lost_answer_reading() {
    for code in [tonic::Code::Unavailable, tonic::Code::Unknown] {
        let err = ProtocolError::from(status_with_markers(code, &[]));
        assert!(
            matches!(err, ProtocolError::Disconnected(_)),
            "an unmarked {code:?} must stay Disconnected, got {err:?}"
        );
    }
    for code in [tonic::Code::Cancelled, tonic::Code::DeadlineExceeded] {
        let err = ProtocolError::from(status_with_markers(code, &[]));
        assert_eq!(answer_lost_code(&err), Some(code));
    }
}

#[test]
fn a_marker_on_a_decisive_code_keeps_the_usual_variant() {
    let attempt = uuid::Uuid::now_v7().to_string();
    let denied = ProtocolError::from(status_with_markers(
        tonic::Code::PermissionDenied,
        &[&attempt],
    ));
    assert!(
        matches!(denied, ProtocolError::NotAuthorized(_)),
        "PermissionDenied must stay NotAuthorized, got {denied:?}"
    );

    let mut unauthenticated = tonic::Status::unauthenticated("bearer audience is wrong");
    unauthenticated.metadata_mut().append(
        lore_transport::outcome::NOT_PREPARED_ATTEMPT_METADATA_KEY,
        attempt.parse().expect("ascii metadata value"),
    );
    let err = ProtocolError::from(unauthenticated);
    assert!(
        matches!(err, ProtocolError::NotAuthenticated(_)),
        "Unauthenticated must stay NotAuthenticated, got {err:?}"
    );
    assert!(
        err.to_string().contains("bearer audience is wrong"),
        "NotAuthenticated must keep the server's reason: {err}"
    );
}

#[test]
fn two_markers_or_an_unparseable_marker_give_no_proof() {
    let first = uuid::Uuid::now_v7().to_string();
    let second = uuid::Uuid::now_v7().to_string();
    for (label, values) in [
        ("two different ids", vec![first.as_str(), second.as_str()]),
        ("the same id twice", vec![first.as_str(), first.as_str()]),
        ("an unparseable value", vec!["not-a-uuid"]),
        ("an empty value", vec![""]),
    ] {
        let err = ProtocolError::from(status_with_markers(tonic::Code::Unavailable, &values));
        assert!(
            matches!(err, ProtocolError::Disconnected(_)),
            "{label} must give no proof and keep the lost-channel reading, got {err:?}"
        );
    }
}

/// A relay re-emits an upstream refusal as a plain `Unavailable`, with no proof: the proof is
/// the upstream server's word about its own copy, not the relay's.
#[test]
fn a_refused_before_prepare_error_converts_back_to_an_unmarked_unavailable() {
    let attempt = uuid::Uuid::now_v7().to_string();
    let err = ProtocolError::from(status_with_markers(tonic::Code::Unavailable, &[&attempt]));
    assert!(is_refused_before_prepare(&err));

    let status = tonic::Status::from(err);
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert!(
        status
            .metadata()
            .get(lore_transport::outcome::NOT_PREPARED_ATTEMPT_METADATA_KEY)
            .is_none(),
        "the relay must not pass the proof on: {:?}",
        status.metadata()
    );
    assert!(
        status.message().contains("verifier unavailable"),
        "the message must survive the relay: {}",
        status.message()
    );

    // And what the next hop's client sees is an ordinary lost channel.
    assert!(matches!(
        ProtocolError::from(status),
        ProtocolError::Disconnected(_)
    ));
}

// --- WP-124 slice 2a: the typed refusal of a declared QUIC session ------------------------------

/// The marker is found by walking the source chain, wherever the error layering put it, and only
/// then. A neighbouring refusal (status 200 `unsupported-client` on a Put) is not it.
#[test]
fn a_quic_declaration_refusal_is_found_through_the_source_chain() {
    for status in [1, 200] {
        let refused = ProtocolError::internal_with_context(
            QuicDeclarationRefused { status },
            "declared storage session refused",
        );
        assert!(is_quic_declaration_refused(&refused), "status {status}");
    }
}

#[test]
fn a_quic_declaration_refusal_survives_one_more_layer_of_context() {
    let inner = ProtocolError::internal_with_context(
        QuicDeclarationRefused { status: 1 },
        "declared storage session refused",
    );
    let outer = ProtocolError::internal_with_context(inner, "opening the managed session");
    assert!(is_quic_declaration_refused(&outer));
}

#[test]
fn other_errors_are_not_a_quic_declaration_refusal() {
    assert!(!is_quic_declaration_refused(&ProtocolError::internal(
        "this transport cannot declare a session"
    )));
    assert!(!is_quic_declaration_refused(&ProtocolError::internal(
        "storage server refused the caller declaration (status 1)"
    )));
    assert!(!is_quic_declaration_refused(&ProtocolError::from(
        tonic::Status::unavailable("server unreachable")
    )));
}

#[test]
fn a_quic_declaration_refusal_names_its_status() {
    let refused = QuicDeclarationRefused { status: 200 };
    assert_eq!(
        refused.to_string(),
        "storage server refused the caller declaration (status 200)"
    );
}
