// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The replay contract for session-bearing storage commands (WP-108 / CR-026).
//!
//! Recreating a session is always safe. Replaying an *operation* is a separate decision, and
//! this module is where that decision is written down once so every recovery path branches on
//! the same answer.
//!
//! Two facts decide it:
//!
//! - [`DispatchState`] — did any request byte reach the wire before the failure?
//! - [`ReplayClass`] — if it did, is repeating the operation harmless?
//!
//! A command that never reached the wire may be rebound onto the replacement connection and
//! sent once under its normal policy. A dispatched read may be retried once. A dispatched
//! mutable command may not be sent again at all: its response is lost, so whether the server
//! applied it is unknown, and [`OutcomeUnknown`] says exactly that rather than claiming the
//! attempt failed.
//!
//! [`ReplayClass`] deliberately has no `Default` and no wildcard classification. Adding a QUIC
//! storage opcode without deciding its replay class is a compile error in
//! [`storage_replay_class`], not a silent read-retryable default.

use std::fmt;

use crate::quic::storage_service::Command;

/// Whether an operation may be sent again after its request was dispatched and its response
/// was lost.
///
/// This is about the operation's effect, not about the transport. Session recreation is safe
/// for both classes; only redispatching the command differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplayClass {
    /// Side-effect-free. The server holds no state that a second identical request would
    /// change, so the command may be rebound and retried once.
    ReadRetryable,
    /// Publishes, revives, or advances server state. Never redispatched after dispatch.
    ///
    /// Content-addressed byte publication is not sufficient to make an operation replay-safe:
    /// `Put` also publishes or revives a repository/context lifecycle association, and an
    /// intervening obliterate can tombstone that association, so a redispatch after an
    /// ambiguous response could resurrect superseded lifecycle intent.
    MutableNoReplay,
}

/// What the transport knows about a failed command's fate.
///
/// The distinction is the whole point of the contract. Exactly one of these three is
/// ambiguous, and only that one may become an [`OutcomeUnknown`]: a command that never reached
/// the wire did not happen, and one the server answered has an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DispatchState {
    /// No request byte reached the wire. The server cannot have observed the command.
    NotDispatched,
    /// Request bytes were written to the stream and no response came back. The server may or
    /// may not have applied the command. This is the ambiguous case, and the only one.
    DispatchedResponseLost,
    /// The server received the command and answered with an error.
    ///
    /// Not ambiguous: an error response is the server declining the operation, so the
    /// operation did not take effect and the command may be sent again under its normal
    /// policy. Collapsing this into [`DispatchState::DispatchedResponseLost`] would report an
    /// ordinary refusal as an unresolvable write.
    DispatchedAndAnswered,
}

/// A dispatched mutable command whose response was lost.
///
/// This is the frozen typed boundary WP-120 consumes. It is deliberately not a message to
/// parse and not a reclassification of some other error: a consumer matches on this type and
/// gets the operation's identity, and nothing here asserts whether the operation committed.
///
/// The transport has no attempt receipt for these commands, so it cannot resolve the
/// ambiguity by asking. A later lifecycle query or readback reports the state *now*, which is
/// conflict context for the adopting caller, not attribution of this attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeUnknown {
    /// The command whose outcome is unknown, by its wire name (see
    /// [`crate::quic::storage_service::command_name`]).
    pub command: &'static str,
}

impl fmt::Display for OutcomeUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: response lost after dispatch, outcome unknown",
            self.command
        )
    }
}

impl std::error::Error for OutcomeUnknown {}

/// The result of a [`ReplayClass::MutableNoReplay`] operation on the typed path.
///
/// The existing untyped operation methods keep returning a plain error for the unknown case,
/// so linking this library does not change what an unadopted caller sees. A caller opts into
/// the distinction by calling the typed method that returns this instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MutableOutcome<T> {
    /// The server answered. The operation was applied.
    Applied(T),
    /// The request was dispatched and its response was lost. Refresh and reconcile
    /// authoritative state; do not treat this as proof the attempt did not commit.
    Unknown(OutcomeUnknown),
}

impl<T> MutableOutcome<T> {
    /// The applied value, or `None` when the outcome is unknown.
    pub fn applied(self) -> Option<T> {
        match self {
            MutableOutcome::Applied(value) => Some(value),
            MutableOutcome::Unknown(_) => None,
        }
    }

    /// Whether this outcome is unknown.
    pub fn is_unknown(&self) -> bool {
        matches!(self, MutableOutcome::Unknown(_))
    }

    /// Rewrite the applied value, leaving an unknown outcome as it is.
    pub fn map<U>(self, project: impl FnOnce(T) -> U) -> MutableOutcome<U> {
        match self {
            MutableOutcome::Applied(value) => MutableOutcome::Applied(project(value)),
            MutableOutcome::Unknown(unknown) => MutableOutcome::Unknown(unknown),
        }
    }
}

/// Dispatches of one caller-visible operation, end to end.
///
/// The operation itself is attempted at most this many times: the original, plus one retry
/// after the session has been rebound onto the replacement connection. Nothing below the
/// session layer starts a loop of its own, and nothing resets this count part-way, so a
/// recovery cannot turn into a retry storm.
///
/// It bounds the *operation*, not every message the recovery sends. Re-establishing a session
/// is a command in its own right and carries its own single retry, so the honest worst case
/// for one caller operation is two dispatches of the operation, at most one replacement
/// `session_start` between them, and at most one reconnect per attempt. Counting the
/// `session_start` as if it were a third attempt of the operation would be as misleading as
/// pretending it costs nothing.
pub const ATTEMPT_BUDGET: u32 = 2;

/// The replay class of a QUIC storage command.
///
/// Exhaustive by construction: there is no wildcard arm, so a new [`Command`] variant does not
/// compile until it is classified here. This is the single construction boundary — every
/// recovery path reads the class from this function rather than deciding locally.
pub fn storage_replay_class(command: Command) -> ReplayClass {
    match command {
        // Side-effect-free reads. A second identical request returns the same answer.
        Command::Get
        | Command::GetMetadata
        | Command::GetResolved
        | Command::Query
        | Command::MutableLoad => ReplayClass::ReadRetryable,

        // Publishes or revives the repository/context lifecycle association for its payload,
        // even though the payload address itself is content-derived and immutable.
        Command::Put | Command::PutResolved | Command::Copy => ReplayClass::MutableNoReplay,

        // Advances a mutable key. A repeat can overwrite a successor value.
        Command::MutableStore | Command::MutableCas => ReplayClass::MutableNoReplay,

        // Carries the heal flag, and the healing variant writes.
        Command::Verify => ReplayClass::MutableNoReplay,

        // Session start and stop. Recreating a session is the recovery this whole contract is
        // built on, so it has to be replayable or the recovery path poisons itself: a lost
        // `session_start` response leaves an orphan the connection's close reaps, and a lost
        // `session_stop` response is idempotent. Neither publishes a lifecycle association nor
        // advances a mutable key, which is what `MutableNoReplay` exists to protect.
        Command::Authorize => ReplayClass::ReadRetryable,
    }
}
