// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use lore_base::error::*;
use lore_error_set::prelude::*;
use thiserror::Error;

/// Typed proof that a session-bearing command was refused before dispatch.
///
/// This stays inside `ProtocolError::Internal`. Making it an error-set variant would widen every
/// strict-forward target in the client API even though only the session layer may act on it.
#[derive(Debug, Clone, Error)]
#[error("Connection replaced; session must be rebound before this command is sent again")]
pub(crate) struct SessionRebindRequired;

/// Typed proof that a status describes the *call* failing rather than the server refusing.
///
/// The exact counterpart of [`SessionRebindRequired`], one step further along: that marker says
/// no byte left, this one says bytes may well have left and the answer did not come back. Both
/// ride inside `ProtocolError::Internal` for the same reason — only one layer of this crate acts
/// on either, and promoting them to error-set variants would widen every strict-forward target
/// in the client API.
///
/// It carries the code so the layer that acts on it can say *why* an outcome went unknown
/// without parsing a message, and the status's own rendering so collapsing into `Internal`
/// costs no diagnostic detail.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{status}")]
pub(crate) struct AnswerLostInTransit {
    code: tonic::Code,
    status: String,
}

impl AnswerLostInTransit {
    fn new(status: &tonic::Status) -> Self {
        Self {
            code: status.code(),
            status: status.to_string(),
        }
    }
}

/// The one shape a lost answer takes as a `ProtocolError`.
///
/// Extracted because four separate discriminators now reach the same conclusion — the funnelled
/// codes, a relay's marker, a status `tonic` derived from a transport failure, and a message
/// `tonic` raises on its own receive path. Four copies of the construction would be four places
/// for the context string to drift out of step with the marker it wraps.
fn answer_lost(status: &tonic::Status) -> ProtocolError {
    ProtocolError::internal_with_context(
        AnswerLostInTransit::new(status),
        "the call failed rather than being refused; its outcome is not settled",
    )
}

/// The header a peer of ours stamps when it re-emits an answer it never received.
///
/// The `Internal` arm below keys off a status's `source`, and `tonic::Status::new` — the only
/// constructor available to [`From<ProtocolError> for tonic::Status`] — builds a sourceless
/// status. So a relayed lost answer arrives stripped of the very property that would re-mark it,
/// and before this header existed the ambiguity died at the second hop even though the first hop
/// forwarded the right code. An explicit header carries the fact itself rather than a property
/// the wire happens to preserve, so it survives any number of hops for every case, not only for
/// the two codes whose arm needs no source.
///
/// Trusted the same way [`crate::outcome::OUTCOME_UNKNOWN_METADATA_KEY`] is: a peer asserting
/// that its own answer went missing is telling the truth about its own call. Believing a peer
/// that lies costs a needless reconciliation, but only within [`is_answer_lost_code`]'s set —
/// outside it the cost would be losing a richer variant, which is why the read is gated.
///
/// Measured residual, not a defect at the reach this topology has: each hop re-renders the
/// previous hop's message inside its own, so the message grows about 2.2x per relay (~120 chars
/// at hop one, ~640 by hop three). A 16 KiB header limit is roughly seven hops away, and Lore
/// relays one or two. A deployment that chains more should raise
/// `ProtocolError::OutcomeUnknown` itself, which carries a fixed-size operation and attempt id
/// rather than a nested rendering.
const ANSWER_LOST_METADATA_KEY: &str = "lore-answer-lost";

/// Versioned so a later hop can widen what the header carries without a silent misread.
const ANSWER_LOST_METADATA_VALUE: &str = "v1";

/// Whether a relaying peer marked this status as an answer it never received.
fn has_answer_lost_marker(status: &tonic::Status) -> bool {
    status
        .metadata()
        .get(ANSWER_LOST_METADATA_KEY)
        .and_then(|value| value.to_str().ok())
        == Some(ANSWER_LOST_METADATA_VALUE)
}

/// `tonic`'s own words for "this client could not read the response", raised sourcelessly.
///
/// `tonic` fails a response on the client's own receive path from seven places, and every one is
/// a lost answer that the plain code mapping reads as decisive or worse. Verified against `tonic`
/// 0.14.6, the version this workspace pins:
///
/// * `client/grpc.rs:253` — `"Missing response message."`: the body ended, the trailers said the
///   call succeeded, and no message came with it.
/// * `codec/decode.rs:273` — `"Unexpected EOF decoding stream."`: the body ended part-way through
///   a length-prefixed message.
/// * `codec/decode.rs:168` — the compressed-flag protocol error, raised with no `grpc-encoding`.
/// * `codec/decode.rs:185` — an invalid compression flag.
/// * `codec/decode.rs:242` — a decompression failure.
/// * `codec/decode.rs:194` — a response message longer than this client's receive limit. Raised
///   as `OutOfRange`, not `Internal`.
/// * `codec/decode.rs:231` — the decompressed response exceeding that limit. Raised as
///   `ResourceExhausted`, not `Internal`.
///
/// In every case the server produced a *message*, which for a mutation means it ran; only this
/// client's ability to read it was lost. That is the strongest form of the ambiguity, not a
/// marginal one.
///
/// **The last two are why this is checked before the code match rather than inside the `Internal`
/// arm, and they were the sharper bug.** `OutOfRange` mapped to `Oversized`, which is merely
/// decisive; but `ResourceExhausted` mapped to `SlowDown`, and `SlowDown` is the one code
/// [`crate::grpc::handle_error`] retries — by relooping the RPC *inside* the `op()` closure, which
/// is beneath `with_reconnect_classified` and therefore beneath the replay class entirely. So a
/// `MutableNoReplay` mutation whose *response* was too big to decompress was not just misreported,
/// it was genuinely reissued, which is the exact outcome the whole replay contract exists to
/// forbid. Found in review of this change; it predates it.
///
/// **Matching on `tonic`'s English is deliberate, and is not the bargain an earlier round of this
/// file judged it to be.** Three things carry it. The strings are `tonic`'s vocabulary about
/// `tonic`'s own decoder state, so a Lore handler cannot collide with one by writing an ordinary
/// refusal. `lore-server` already depends on exactly one of them the same way
/// (`interpret_streaming_error`, `lore-server/src/grpc/mod.rs`, matches
/// `"Unexpected EOF decoding stream."` verbatim), so the coupling is upstream's own, not something
/// introduced here. And the failure direction is the safe one: a refusal misread as a lost answer
/// costs one reconciliation and can never be reissued, because
/// `with_reconnect_classified` turns it into `ProtocolError::OutcomeUnknown`, which is a peer of
/// `Disconnected` precisely so no reconnect path replays it. A lost answer misread as a refusal is
/// what escalated a mid-flight lock release to a force-release.
///
/// If `tonic` reworded one of these, the arm stops firing and the behaviour falls back to exactly
/// today's gap — a silent regression, not a new hazard. The unit cases below drive each string, so
/// a version bump that reworded one leaves the test green while the pin's own comment names the
/// version it was verified against; the live proof is `lore/tests/live_lock_journal.rs`.
///
/// Two of the seven are direction-dependent, and are matched only in their **response**
/// rendering. `tonic` appends `"while receiving response with status: {status}"` when a decoder is
/// reading a response and `", while sending request"` when it is reading a request, and only the
/// first is this client's own receive path. The second reaches us relayed from a server that could
/// not decode what we sent, which means the handler never ran: a genuine decisive outcome that
/// must keep reading as one. The two renderings differ in their punctuation before the clause
/// (`decode.rs:178` has no comma, `decode.rs:237` does), so the clause is matched with `contains`
/// rather than by reconstructing the whole string.
fn is_tonic_lost_response(status: &tonic::Status) -> bool {
    /// `client/grpc.rs`. Note the sibling `"Missing request message."` (`server/grpc.rs`) is a
    /// *server* raising that it never decoded our request — never applied, and never matched here.
    const MISSING_RESPONSE_MESSAGE: &str = "Missing response message.";
    /// `codec/decode.rs`.
    const UNEXPECTED_EOF: &str = "Unexpected EOF decoding stream.";
    /// `codec/decode.rs`. Fixed text, and raised in both directions; a request-direction sighting
    /// is a server that could not decode our message, so believing it costs a reconciliation and
    /// nothing more.
    const COMPRESSED_FLAG_WITHOUT_ENCODING: &str =
        "protocol error: received message with compressed-flag but no grpc-encoding was specified";
    /// `codec/decode.rs`, prefix only — the flag byte is interpolated.
    const INVALID_COMPRESSION_FLAG: &str =
        "protocol error: received message with invalid compression flag: ";
    /// `codec/decode.rs`, prefix only — the io error is interpolated.
    const DECOMPRESSION_FAILED: &str = "Error decompressing: ";
    /// The clause `tonic` appends only in `Direction::Response`, which is what makes the two
    /// interpolated sites above safe to match by prefix.
    const RECEIVING_RESPONSE: &str = "while receiving response with status: ";
    /// `codec/decode.rs`, the `OutOfRange` site. Prefix only — both byte counts are interpolated.
    const MESSAGE_TOO_LARGE: &str = "Error, decoded message length too large: found ";
    /// `codec/decode.rs`, the `ResourceExhausted` site. It shares
    /// [`DECOMPRESSION_FAILED`]'s prefix but carries no direction clause, so it is matched on its
    /// own shape and must be tested BEFORE the direction-dependent rule below would reject it.
    const DECOMPRESS_LIMIT_PREFIX: &str = "Error decompressing: size limit, of ";
    /// The tail of that same message.
    const DECOMPRESS_LIMIT_SUFFIX: &str = "exceeded while decompressing message";

    let message = status.message();
    message == MISSING_RESPONSE_MESSAGE
        || message == UNEXPECTED_EOF
        || message == COMPRESSED_FLAG_WITHOUT_ENCODING
        || message.starts_with(MESSAGE_TOO_LARGE)
        || (message.starts_with(DECOMPRESS_LIMIT_PREFIX)
            && message.contains(DECOMPRESS_LIMIT_SUFFIX))
        || ((message.starts_with(INVALID_COMPRESSION_FLAG)
            || message.starts_with(DECOMPRESSION_FAILED))
            && message.contains(RECEIVING_RESPONSE))
}

/// The codes this crate can attach [`ANSWER_LOST_METADATA_KEY`] to.
///
/// The header is honoured only on one of these. Without the gate, a peer that stamped the header
/// on an `Unauthenticated` would have this client answer `ProtocolError::Internal` instead of
/// `NotAuthenticated`, throwing away the refusal reason that the `Unauthenticated` arm below
/// exists to carry — a strictly worse error, not just a needless reconciliation. Found in review.
///
/// This is input validation against a set this crate closes, not the per-branch guard the file
/// refuses to write: the marker is minted in exactly one place, from a status whose code is
/// already one of these five, so a header on any other code is a bug or a hostile peer. **A new
/// marking site whose code is not in this list must add it here**, or its marker will be dropped
/// at the first relay hop.
fn is_answer_lost_code(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Internal
            | tonic::Code::OutOfRange
            | tonic::Code::ResourceExhausted
    )
}

/// The gRPC code behind a lost answer, when the error carries that proof.
///
/// A source-chain walk rather than a variant check, exactly as
/// [`is_session_rebind_required`] is: the proof is attached where the status is converted, and
/// every layer between there and the replay decision wraps rather than inspects.
///
/// Returns the code rather than a bare `bool` so a caller can report which failure produced the
/// ambiguity, and so the field cannot rot into something only a test reads.
pub(crate) fn answer_lost_code(error: &ProtocolError) -> Option<tonic::Code> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(source) = current {
        if let Some(lost) = source.downcast_ref::<AnswerLostInTransit>() {
            return Some(lost.code);
        }
        current = source.source();
    }
    None
}

#[error_set(clone)]
pub enum ProtocolError {
    Disconnected,
    SlowDown,
    NotAuthorized,
    NotAuthenticated,
    Maintenance,
    NotFound,
    NoRemote,
    NotSupported,
    Oversized,
    /// A dispatched mutable request whose outcome is not known (WP-120).
    ///
    /// Deliberately a peer of `Disconnected` rather than a shade of it. Every reconnect and
    /// reissue path in this crate branches on `Disconnected`, so an unknown outcome that
    /// answered to that predicate would be replayed by all of them — which is the one thing
    /// it must never be. It is built in exactly one place,
    /// [`crate::outcome::resolve`].
    OutcomeUnknown,
}

pub(crate) fn is_session_rebind_required(error: &ProtocolError) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(source) = current {
        if source.downcast_ref::<SessionRebindRequired>().is_some() {
            return true;
        }
        current = source.source();
    }
    false
}

impl From<tonic::Status> for ProtocolError {
    fn from(value: tonic::Status) -> Self {
        // Checked once, before any branch on the code, for the reason the QUIC classifier
        // checks its own orthogonal property once: a per-arm check is a promise every future
        // arm has to remember to repeat, and arms do not.
        //
        // The marker is what a server sets when *it* knows its result was indeterminate. It is
        // not inferred from `Code::Unknown`, which only means the server did not classify the
        // failure — an unmarked status stays the ordinary protocol error it always was, and a
        // lost *mutable* response is upgraded independently by the caller's own dispatch
        // classification in `crate::outcome`.
        if let Some(unknown) = outcome_unknown_marker(&value) {
            return ProtocolError::from(unknown);
        }
        // Checked second, and once, for the same reason. It is the weaker of the two markers —
        // it names no operation and no attempt — so a status carrying both is read as the
        // unknown outcome the server actually identified, not as this client's inference.
        if has_answer_lost_marker(&value) && is_answer_lost_code(value.code()) {
            return answer_lost(&value);
        }
        // Checked third, and once, before any branch on the code — which is the point.
        // [`is_tonic_lost_response`] covers two codes that are not `Internal`, and one of them
        // (`ResourceExhausted`) reaches a retry loop rather than merely a wrong verdict, so a
        // guard living inside a single arm would leave the sharper half of the bug open. The
        // property is orthogonal to the code, so it is tested once against the code axis rather
        // than repeated on the arms that happen to need it today.
        if is_tonic_lost_response(&value) {
            return answer_lost(&value);
        }
        match value.code() {
            tonic::Code::Unavailable | tonic::Code::Unknown => ProtocolError::from(Disconnected),
            tonic::Code::Unauthenticated => {
                // The server's own words are the whole diagnostic value of this
                // arm, so they are CARRIED, not merely logged. An enforcing cell
                // refuses a push for a precise, actionable cause ("bearer audience
                // ... is not the human authn audience"); before `NotAuthenticated`
                // had a reason field that cause died here and the operator saw
                // three characterless words, which cost a full diagnosis session
                // on WP-120.
                //
                // A status with no message still has to produce a readable error,
                // so an empty one falls back to the named constant rather than
                // rendering "Not authenticated: ".
                let message = value.message();
                let reason = if message.trim().is_empty() {
                    lore_base::error::UNSTATED_REFUSAL
                } else {
                    message
                };
                ProtocolError::from(NotAuthenticated::new(reason))
            }
            tonic::Code::PermissionDenied => ProtocolError::from(NotAuthorized),
            tonic::Code::NotFound => ProtocolError::from(NotFound),
            tonic::Code::ResourceExhausted => ProtocolError::from(SlowDown),
            tonic::Code::OutOfRange => ProtocolError::from(Oversized {
                context: value.message().to_string(),
            }),
            tonic::Code::Unimplemented => ProtocolError::from(NotSupported {
                operation: value.message().to_string(),
            }),
            // A cancelled or timed-out call is never the server's verdict on the request.
            //
            // Neither code is a refusal in the sense that matters. The lock handlers refuse with
            // `NotFound`, `FailedPrecondition`, `ResourceExhausted`, `InvalidArgument` or
            // `Internal` (`lore-server/src/grpc/lock_service.rs`'s `handle_lock_error`), and
            // nothing there reaches for either of these. The two ways they do arrive both leave
            // the outcome open:
            //
            // * `tonic`'s own client machinery — an h2 `CANCEL` on a stream the peer reset
            //   mid-flight, a hyper cancellation, or a `grpc-timeout` that expired
            //   (`Status::code_from_h2`, and `find_status_in_source_chain`'s `TimeoutExpired`
            //   arm, both of which produce `Code::Cancelled`).
            // * `lore-server`'s own `timeout_grpc` (`lore-server/src/grpc/mod.rs`), which wraps
            //   every lock handler and answers `Status::cancelled("Request handler timeout
            //   exceeded")` when the handler outruns its budget. Found in review, and it is not
            //   a counter-example: `timeout` drops the handler future part-way, so a durable
            //   step already taken stands and the server itself does not know what it applied.
            //
            // gRPC says the same thing about the deadline in its own words: it "may be returned
            // even if the operation has completed successfully", because a successful response
            // can be delayed past the deadline.
            //
            // So the request may well have been applied and the answer lost, which is a
            // different fact from a refusal and has to survive as one. What the layer that reads
            // this marker does with it depends on the operation's replay class, and deciding
            // that here would be the per-branch guard this file already refuses to write.
            tonic::Code::Cancelled | tonic::Code::DeadlineExceeded => answer_lost(&value),
            // `Internal` is the one funnelled code a server does raise deliberately, so it is
            // split rather than reclassified wholesale.
            //
            // A status the server produced is built by `tonic::Status::new`, which leaves
            // `source` empty; a status `tonic` derived from a transport failure carries the
            // underlying error as its source, in every path that can reach a client — the h2
            // protocol errors that `code_from_h2` maps to `Internal` (`NO_ERROR` on a
            // `RST_STREAM`, `PROTOCOL_ERROR`, `INTERNAL_ERROR`, `FLOW_CONTROL_ERROR`,
            // `SETTINGS_TIMEOUT`, `COMPRESSION_ERROR`, `CONNECT_ERROR`) are attached by
            // `from_h2_error`, and everything routed through `try_from_error` has its source
            // stamped on before it is returned. The presence of a source is therefore the
            // discriminator, and it errs in the safe direction: a server refusal read as a lost
            // answer would cost a needless reconciliation, while a lost answer read as a refusal
            // is what let a mid-flight reset escalate to a force-release.
            //
            // The sourceless residual this arm used to leave open is handled above, by
            // [`is_tonic_lost_response`], which runs before this match reaches any code at all.
            // Read that function's doc comment before changing this guard: it records which
            // `tonic` sites are matched, which are deliberately left decisive, and why matching
            // `tonic`'s English is the sound trade here rather than the bad bargain an earlier
            // round of this file took it for.
            //
            // What remains open is narrower and is not a defect: a *handler* that builds
            // `Status::internal` for a refusal is decisive, which is correct, and the send-side
            // and request-direction decoder errors (`"Error encoding: …"`,
            // `"Missing request message."`, the `", while sending request"` renderings) are
            // decisive because the handler provably never ran on that message.
            tonic::Code::Internal if std::error::Error::source(&value).is_some() => {
                answer_lost(&value)
            }
            _ => ProtocolError::internal(value.to_string()),
        }
    }
}

/// What an attempt id reads as when the server marked an outcome unknown without naming one.
///
/// Deliberately not an empty string: it reaches a human in an error message and a caller's
/// journal, and "no id was supplied" is a different fact from "the id is blank".
pub(crate) const UNNAMED_ATTEMPT: &str = "unnamed";

/// Read a server's semantic unknown-outcome marker off a status, if it set one.
///
/// Returns the discrete error already populated with the operation and attempt the server
/// named, falling back to the status's own text when it named neither — an unknown outcome
/// with a weak identity is still an unknown outcome, and dropping it because the identity is
/// thin would turn it back into the retryable error the whole contract exists to avoid.
fn outcome_unknown_marker(status: &tonic::Status) -> Option<OutcomeUnknown> {
    let metadata = status.metadata();
    let text = |key: &str| {
        metadata
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };

    if text(crate::outcome::OUTCOME_UNKNOWN_METADATA_KEY).as_deref()
        != Some(crate::outcome::OUTCOME_UNKNOWN_METADATA_VALUE)
    {
        return None;
    }

    Some(OutcomeUnknown {
        operation: text(crate::outcome::OUTCOME_UNKNOWN_OPERATION_KEY)
            .unwrap_or_else(|| status.message().to_string()),
        // Named rather than left empty. A server that marked the outcome unknown without
        // naming an attempt has told the caller something real, and rendering the gap as
        // `(attempt )` reads as a bug in this client rather than as a thin marker.
        attempt_id: text(crate::outcome::OUTCOME_UNKNOWN_ATTEMPT_KEY)
            .unwrap_or_else(|| UNNAMED_ATTEMPT.to_string()),
    })
}

impl From<ProtocolError> for tonic::Status {
    fn from(value: ProtocolError) -> Self {
        let msg = value.to_string();
        if let ProtocolError::OutcomeUnknown(unknown) = &value {
            let mut status = tonic::Status::new(tonic::Code::Unknown, msg);
            let metadata = status.metadata_mut();
            insert_marker(
                metadata,
                crate::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
                crate::outcome::OUTCOME_UNKNOWN_METADATA_VALUE,
            );
            insert_marker(
                metadata,
                crate::outcome::OUTCOME_UNKNOWN_OPERATION_KEY,
                &unknown.operation,
            );
            insert_marker(
                metadata,
                crate::outcome::OUTCOME_UNKNOWN_ATTEMPT_KEY,
                &unknown.attempt_id,
            );
            return status;
        }
        // Re-emit the code the marker recorded, before the `Internal` arm below flattens it.
        //
        // Checked here, once, for the same reason the unknown-outcome marker is checked once on
        // the way in. A relaying server that answered `Internal` for what reached it as a
        // cancelled or timed-out call would hand its own client a decisive refusal, and the
        // ambiguity this whole marker exists to carry would die at the one hop that was supposed
        // to forward it. Found in review, by round-tripping a marked `Cancelled` and watching it
        // come back as `Code::Internal` with no marker left on it.
        //
        // It restores the code *and* stamps the fact, and the second half is what makes the
        // reach uniform. Restoring the code alone was a one-hop fix for two of the three cases:
        // `Cancelled` and `DeadlineExceeded` re-mark on arrival because their arm keys off the
        // code alone, but a sourced `Internal` does not, because `tonic::Status::new` builds a
        // sourceless status and sourcelessness is the one property that arm cannot tolerate. So
        // the ambiguity used to die at the second hop for exactly the case that needed a relay
        // most. [`ANSWER_LOST_METADATA_KEY`] carries the fact itself instead of relying on a
        // property of the wire, so every case now survives every hop.
        if let Some(code) = answer_lost_code(&value) {
            let mut status = tonic::Status::new(code, msg);
            insert_marker(
                status.metadata_mut(),
                ANSWER_LOST_METADATA_KEY,
                ANSWER_LOST_METADATA_VALUE,
            );
            return status;
        }
        match value {
            ProtocolError::NotAuthenticated(_) => {
                tonic::Status::new(tonic::Code::Unauthenticated, msg)
            }
            ProtocolError::NotAuthorized(_) => {
                tonic::Status::new(tonic::Code::PermissionDenied, msg)
            }
            ProtocolError::SlowDown(_) => tonic::Status::new(tonic::Code::ResourceExhausted, msg),
            ProtocolError::NotFound(_) => tonic::Status::new(tonic::Code::NotFound, msg),
            ProtocolError::Oversized(_) => tonic::Status::new(tonic::Code::OutOfRange, msg),
            ProtocolError::Disconnected(_) | ProtocolError::Maintenance(_) => {
                tonic::Status::new(tonic::Code::Unavailable, msg)
            }
            ProtocolError::NotSupported(_) => tonic::Status::new(tonic::Code::Unimplemented, msg),
            ProtocolError::NoRemote(_) | ProtocolError::Internal(_) => {
                tonic::Status::new(tonic::Code::Internal, msg)
            }
            // Handled above, where the marker metadata is attached.
            ProtocolError::OutcomeUnknown(_) => tonic::Status::new(tonic::Code::Unknown, msg),
        }
    }
}

/// Attach one marker header, skipping a value gRPC metadata cannot carry.
///
/// A header that will not encode is dropped rather than failing the conversion: losing the
/// operation name degrades the detail, while failing the conversion would lose the unknown
/// outcome itself.
fn insert_marker(metadata: &mut tonic::metadata::MetadataMap, key: &'static str, value: &str) {
    if let Ok(value) = value.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()
        && let Ok(key) = key.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>()
    {
        metadata.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                crate::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
                crate::outcome::OUTCOME_UNKNOWN_METADATA_VALUE,
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
        let status =
            tonic::Status::resource_exhausted("Error decompressing: size limit, of 5 bytes");
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
}
