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
            tonic::Code::Cancelled | tonic::Code::DeadlineExceeded => {
                ProtocolError::internal_with_context(
                    AnswerLostInTransit::new(&value),
                    "the call failed rather than being refused; its outcome is not settled",
                )
            }
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
            // Known residual, measured in review rather than guessed at, and larger than one
            // site: `tonic` raises a sourceless `Internal` from four places on the client's own
            // response path — `Status::internal("Missing response message.")`
            // (`client/grpc.rs`), the compressed-flag protocol error, the two message-too-large
            // errors, and `"Unexpected EOF decoding stream."` (`codec/decode.rs`). Every one is
            // a lost answer that this rule still reads as decisive, so the original defect
            // survives for a mutation whose answer dies in decoding rather than in transit.
            //
            // It is left open deliberately. There is no signal at this boundary that separates
            // them from a server refusal: a status the server sent arrives sourceless too
            // (verified on the wire — a returned `Status::internal` reaches the client with no
            // source), so the only available discriminator would be the message text, and
            // pinning a client's mutation safety to four `tonic`-internal English strings is a
            // worse bargain than the gap. Closing it properly needs a dispatch fact this
            // transport does not have for a unary RPC, the way `StreamCache::request` has one
            // for a stream.
            tonic::Code::Internal if std::error::Error::source(&value).is_some() => {
                ProtocolError::internal_with_context(
                    AnswerLostInTransit::new(&value),
                    "the call failed rather than being refused; its outcome is not settled",
                )
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
        // It restores the code, not the marker, and the two are not the same reach. `Cancelled`
        // and `DeadlineExceeded` re-mark on the next hop because their arm keys off the code
        // alone, so the ambiguity survives arbitrarily far. A sourced `Internal` does not:
        // `tonic::Status::new` builds a sourceless status, which is exactly the property that
        // arm requires, so the next hop reads it as an ordinary decisive `Internal`. Both facts
        // are pinned by test. A relay that needs full fidelity for that case should raise
        // `ProtocolError::OutcomeUnknown` itself, which carries its own wire metadata a few
        // lines above and is the mechanism built for exactly this.
        if let Some(code) = answer_lost_code(&value) {
            return tonic::Status::new(code, msg);
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

    /// Unlike `Cancelled`/`DeadlineExceeded`, a sourced-`Internal` marker does NOT survive a
    /// second hop, and this test pins that as a real, verified property rather than assuming
    /// symmetry with its two siblings above.
    ///
    /// `From<ProtocolError> for tonic::Status`'s early return always builds the outgoing status
    /// with `tonic::Status::new(code, msg)`, and `tonic::Status::new` always leaves `source: None`
    /// (`status.rs`). The forward conversion's `Internal` arm only marks a status that STILL has a
    /// source (`tonic::Code::Internal if std::error::Error::source(&value).is_some()`), so a
    /// round-tripped sourced-`Internal` has lost the very property that got it marked in the
    /// first place, and reconverting it lands in the plain `_` arm as a decisive `Internal`. The
    /// first hop's `Code::Internal` on the wire is still correct -- a relaying server's own
    /// caller sees the right code -- but the marker itself is a one-hop fact for this code,
    /// unlike `Cancelled`/`DeadlineExceeded`'s code-only, no-source-required arm.
    #[test]
    fn sourced_internal_status_round_trips_to_internal_code_but_the_marker_does_not_survive_a_second_hop()
     {
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
            "sanity: this is the mechanism -- the outgoing status built by the early return is \
             always sourceless, which is what strips the property the Internal arm needs to \
             re-mark"
        );

        let reconverted = ProtocolError::from(round_tripped);
        assert_eq!(
            answer_lost_code(&reconverted),
            None,
            "documented, verified gap: a sourced Internal's marker does not survive a second hop \
             the way Cancelled/DeadlineExceeded's does, because the round-tripped status is \
             sourceless and the Internal arm requires a source. If this ever starts returning \
             Some(_), that is a real close of the gap (e.g. the outgoing status started \
             preserving a source) -- update this test's expectation and this comment together \
             rather than treating the new green as a break"
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

    // --- Known-limitation pin: the still-open residual named in error.rs's own comment ---
    //
    // `tonic` itself raises these two exact messages as a sourceless `Status::internal(...)` for
    // a response that ends without ever producing a message -- confirmed against tonic 0.14.6:
    // `client/grpc.rs:253` ("Missing response message.") and `codec/decode.rs:168/185/242/273`
    // ("Unexpected EOF decoding stream."). Both are genuine lost answers -- the call ended
    // without a real verdict -- that this crate currently classifies as DECISIVE, because they
    // carry no source to key off of and no code that distinguishes them from an ordinary refusal.
    // Closing this would need matching on the message text (a worse bargain than leaving it, per
    // error.rs's own comment) or a different signal entirely.
    #[test]
    fn known_gap_sourceless_stream_truncation_internal_statuses_read_as_decisive() {
        for message in [
            "Missing response message.",
            "Unexpected EOF decoding stream.",
        ] {
            let status = tonic::Status::internal(message);
            assert!(
                std::error::Error::source(&status).is_none(),
                "sanity: {message:?} is sourceless when tonic raises it, which is exactly what \
                 keeps it unmarked below"
            );
            let err = ProtocolError::from(status);
            assert_eq!(
                answer_lost_code(&err),
                None,
                "documented gap: {message:?} is a genuine lost answer that currently reads as a \
                 decisive Internal. If this ever starts returning Some(_), that is a real close \
                 of the gap -- update this test's expectation and the comment above together \
                 rather than treating the new green as a break"
            );
        }
    }
}
