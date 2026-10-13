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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported client capability")]
pub struct UnsupportedClientCapability;

pub fn is_unsupported_client(error: &ProtocolError) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(source) = current {
        if source
            .downcast_ref::<UnsupportedClientCapability>()
            .is_some()
        {
            return true;
        }
        current = source.source();
    }
    false
}

pub fn is_unsupported_client_status(status: &tonic::Status) -> bool {
    let mut values = status.metadata().get_all("lore-client-admission-v1").iter();
    status.code() == tonic::Code::FailedPrecondition
        && values.next().and_then(|value| value.to_str().ok()) == Some("unsupported-client")
        && values.next().is_none()
}

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
#[lore_macro::test_pub]
const ANSWER_LOST_METADATA_KEY: &str = "lore-answer-lost";

/// Versioned so a later hop can widen what the header carries without a silent misread.
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
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

/// Typed proof that a loreserver refused a mutation before it prepared any receipt for it.
///
/// Built only from a status carrying [`crate::outcome::NOT_PREPARED_ATTEMPT_METADATA_KEY`] whose
/// code would otherwise read as a lost answer. It rides inside `ProtocolError::Internal` for the
/// same reason [`AnswerLostInTransit`] does, and the one layer that acts on it,
/// `with_reconnect_classified`, settles the attempt only when the proof names that attempt and the
/// attempt was sent once. Anywhere else it is an ordinary decisive refusal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{status}")]
pub(crate) struct RefusedBeforePrepare {
    attempt: uuid::Uuid,
    status: String,
}

/// The codes whose plain mapping reads as a lost answer, and so the only codes the not-prepared
/// proof changes. Every other code already maps to a decisive refusal and keeps its richer
/// variant (`NotAuthenticated`, `NotAuthorized`, ...), so the proof is ignored on it.
fn is_unsettled_code(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::Unavailable
            | tonic::Code::Unknown
            | tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
    )
}

/// Read the server's not-prepared proof off a status, if it set a well-formed one.
fn not_prepared_marker(status: &tonic::Status) -> Option<uuid::Uuid> {
    let mut values = status
        .metadata()
        .get_all(crate::outcome::NOT_PREPARED_ATTEMPT_METADATA_KEY)
        .iter();
    let value = values.next()?;
    // Two values is not a proof about one attempt.
    if values.next().is_some() {
        return None;
    }
    uuid::Uuid::parse_str(value.to_str().ok()?).ok()
}

/// The attempt a not-prepared proof names, when the error carries one.
pub(crate) fn not_prepared_attempt(error: &ProtocolError) -> Option<uuid::Uuid> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(source) = current {
        if let Some(refused) = source.downcast_ref::<RefusedBeforePrepare>() {
            return Some(refused.attempt);
        }
        current = source.source();
    }
    None
}

use crate::grpc::address_not_found_details;
use crate::grpc::address_not_found_status;

#[error_set(clone)]
pub enum ProtocolError {
    Disconnected,
    SlowDown,
    NotAuthorized,
    NotAuthenticated,
    Maintenance,
    NotFound,
    AddressNotFound,
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
        if is_unsupported_client_status(&value) {
            return Self::internal_with_context(
                UnsupportedClientCapability,
                "client admission refused before dispatch",
            );
        }
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
        // Checked last of the four, so either sign of a lost answer above outranks it: the proof
        // speaks for a refusal the server sent, not for one a relay or this client inferred.
        if is_unsettled_code(value.code())
            && let Some(attempt) = not_prepared_marker(&value)
        {
            return ProtocolError::internal_with_context(
                RefusedBeforePrepare {
                    attempt,
                    status: value.to_string(),
                },
                "the server refused this request before preparing it",
            );
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
            tonic::Code::FailedPrecondition => match address_not_found_details(&value) {
                Some(error) => ProtocolError::from(error),
                None => ProtocolError::internal_with_context(value, "remote rejected the request"),
            },
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
        // A relaying peer re-emits an upstream not-prepared refusal as a plain `Unavailable`,
        // without the proof. The proof is the upstream server's word about its own copy; the
        // relay's own client never sent that copy, so for it the outcome stays unknown.
        if not_prepared_attempt(&value).is_some() {
            return tonic::Status::new(tonic::Code::Unavailable, msg);
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
            ProtocolError::AddressNotFound(error) => address_not_found_status(&error, msg),
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
#[lore_macro::test_pub]
fn insert_marker(metadata: &mut tonic::metadata::MetadataMap, key: &'static str, value: &str) {
    if let Ok(value) = value.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()
        && let Ok(key) = key.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>()
    {
        metadata.insert(key, value);
    }
}
