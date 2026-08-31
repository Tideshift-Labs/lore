// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// WP-108 / CR-026 replay contract fixtures.
//
// [CLIENT]-class: `lore-transport` is a client-path crate. These are pure, offline fixtures with
// no live server -- an external test target (not an inline `#[cfg(test)] mod`) so a name
// collision with `lore-transport/src/quic/client.rs`'s or `session.rs`'s own `mod tests` is
// structurally impossible, and so this file exercises ONLY the crate's public surface, the same
// surface WP-120 will link against.
//
// B12: exhaustive, no-default classification of every `Command` variant. Written as a `match`
// with no `_` arm on purpose -- a new QUIC command that lands without an explicit replay
// classification must fail to compile here, not silently default to some class.
//
// B13: frozen handoff fixture. WP-120 needs to consume `MutableOutcome`/`OutcomeUnknown` through
// nothing but `lore_transport`'s public re-exports, with no message parsing and no
// reclassification of its own. This file proves that shape is reachable and stable, and is
// deliberately small: WP-120 links against it, so it should not need to change when unrelated
// storage-service surface changes.
//
// CORRECTION (2026-08-30, from the WP-108 implementation agent): `Authorize` is `ReadRetryable`,
// not `MutableNoReplay` as originally briefed. Session recreation is always safe -- CR-026 and
// WP-108 both say so -- and `Authorize` carries `session_start`/`session_stop`, which IS session
// recreation. A lost `session_start` response leaves an orphan session the connection close reaps;
// a lost `session_stop` response is idempotent. Neither publishes a lifecycle association nor
// advances a mutable key, which is what `MutableNoReplay` exists to protect, and classifying it
// `MutableNoReplay` would make a lost `session_start` response return `OutcomeUnknown` and poison
// the rebind path the whole fix depends on. Verified directly against
// `lore-transport/src/replay.rs`'s `storage_replay_class` before writing this fixture.
//
// CORRECTION 2 (2026-08-30): `DispatchState` gained a third variant, `DispatchedAndAnswered` --
// the server received the command and answered with an error, which is not ambiguous (an
// ordinary refusal, not a lost write). Verified against `lore-transport/src/replay.rs` directly.
// The exhaustive match below (`is_ambiguous`) had to grow to cover it, which is exactly the
// no-default guard this fixture exists to provide.

use lore_transport::ATTEMPT_BUDGET;
use lore_transport::DispatchState;
use lore_transport::MutableOutcome;
use lore_transport::OutcomeUnknown;
use lore_transport::ReplayClass;
use lore_transport::quic::storage_service::Command;
use lore_transport::storage_replay_class;

/// B12: every `Command` variant classified by name, exhaustively. Adding a 13th `Command` variant
/// without extending this match is a compile error, not a silently-defaulted class.
fn classify(command: Command) -> ReplayClass {
    match command {
        Command::Get => ReplayClass::ReadRetryable,
        Command::GetMetadata => ReplayClass::ReadRetryable,
        Command::GetResolved => ReplayClass::ReadRetryable,
        Command::Query => ReplayClass::ReadRetryable,
        Command::MutableLoad => ReplayClass::ReadRetryable,
        Command::Put => ReplayClass::MutableNoReplay,
        Command::PutResolved => ReplayClass::MutableNoReplay,
        Command::MutableStore => ReplayClass::MutableNoReplay,
        Command::MutableCas => ReplayClass::MutableNoReplay,
        Command::Copy => ReplayClass::MutableNoReplay,
        // `Verify` carries the heal flag; the healing variant writes, so it must never be
        // blindly replayed even though a non-healing verify only reads.
        Command::Verify => ReplayClass::MutableNoReplay,
        // Session start/stop. Recreating a session is the recovery this whole contract is built
        // on, so it has to be replayable: a lost `session_start` response leaves an orphan the
        // connection close reaps, and a lost `session_stop` response is idempotent. Neither
        // publishes a lifecycle association nor advances a mutable key.
        Command::Authorize => ReplayClass::ReadRetryable,
    }
}

/// The fixture's own classification (above) must agree with the production classifier for every
/// variant -- this is the actual CR-026 pin, not just that `classify` compiles exhaustively.
#[test]
fn every_command_variant_matches_the_normative_cr_026_classification() {
    let read_retryable = [
        Command::Get,
        Command::GetMetadata,
        Command::GetResolved,
        Command::Query,
        Command::MutableLoad,
        Command::Authorize,
    ];
    let mutable_no_replay = [
        Command::Put,
        Command::PutResolved,
        Command::MutableStore,
        Command::MutableCas,
        Command::Copy,
        Command::Verify,
    ];

    // 12 total: 6 read-retryable + 6 mutable-no-replay. If this count ever drifts, a variant was
    // added to `Command` without a corresponding entry in one of these two lists above.
    assert_eq!(read_retryable.len() + mutable_no_replay.len(), 12);

    for command in read_retryable {
        assert_eq!(
            storage_replay_class(command),
            ReplayClass::ReadRetryable,
            "{command} must classify as ReadRetryable"
        );
        assert_eq!(
            classify(command),
            ReplayClass::ReadRetryable,
            "fixture and production classifier disagree on {command}"
        );
    }

    for command in mutable_no_replay {
        assert_eq!(
            storage_replay_class(command),
            ReplayClass::MutableNoReplay,
            "{command} must classify as MutableNoReplay"
        );
        assert_eq!(
            classify(command),
            ReplayClass::MutableNoReplay,
            "fixture and production classifier disagree on {command}"
        );
    }
}

/// `Verify` is `MutableNoReplay` specifically because of the heal flag, not because verification
/// in general is a write -- pin the reason, not just the class, so a future refactor that splits
/// `Verify`/`VerifyHeal` into two commands has to reconsider this rather than copy the class.
#[test]
fn verify_is_mutable_no_replay_because_it_carries_the_heal_flag() {
    assert_eq!(
        storage_replay_class(Command::Verify),
        ReplayClass::MutableNoReplay,
        "Verify carries the heal flag; the healing variant writes, so a lost response must \
         never be blindly replayed even for the common non-healing case"
    );
}

/// `Authorize` is `ReadRetryable`, not because session establishment is side-effect-free (it
/// plainly is not), but because RECREATING a session is always safe -- it is the recovery this
/// whole contract exists to enable, so it must not itself be blocked by the contract. A lost
/// `session_start` response leaves an orphan session the connection's own close reaps; a lost
/// `session_stop` response is idempotent (stopping an already-stopped or unknown session is a
/// no-op). Classifying `Authorize` as `MutableNoReplay` would make a lost `session_start`
/// response return `OutcomeUnknown` and poison the rebind path itself.
#[test]
fn authorize_is_read_retryable_because_session_recreation_is_always_safe() {
    assert_eq!(
        storage_replay_class(Command::Authorize),
        ReplayClass::ReadRetryable
    );
}

/// B6 (partial, offline half): the shared end-to-end attempt budget is exactly 2. This is the ONE
/// budget every layer (transport reconnect, session rebind, auth refresh, operation policy,
/// caller) must consult -- not a per-layer count. The "no layer nests or resets it" half of B6
/// needs a live, multi-layer fault-injection harness and is NOT proven by this pure fixture; see
/// the WP-108 test-specialist report for what that would require.
#[test]
fn attempt_budget_is_exactly_two() {
    assert_eq!(ATTEMPT_BUDGET, 2);
}

/// `DispatchState` has three variants now (the implementation added `DispatchedAndAnswered`
/// after the original brief was written -- see the exhaustive match below, which had to grow
/// with it). Exactly one is ambiguous. This fixture is the no-default guard for that: a fourth
/// `DispatchState` variant fails to compile here until this match says whether it is ambiguous.
fn is_ambiguous(state: DispatchState) -> bool {
    match state {
        DispatchState::NotDispatched => false,
        DispatchState::DispatchedResponseLost => true,
        // The server received the command and declined it. Not ambiguous -- the operation did
        // not take effect, so it is an ordinary failure, not an unresolvable write. Collapsing
        // this into `DispatchedResponseLost` would report a plain refusal (`NotFound`,
        // `SlowDown`, a server error status) arriving during a reconnect race as
        // `OutcomeUnknown`, which is a false positive the caller cannot safely reconcile away.
        DispatchState::DispatchedAndAnswered => false,
    }
}

#[test]
fn only_dispatched_response_lost_is_ambiguous() {
    assert!(!is_ambiguous(DispatchState::NotDispatched));
    assert!(is_ambiguous(DispatchState::DispatchedResponseLost));
    assert!(
        !is_ambiguous(DispatchState::DispatchedAndAnswered),
        "a real server error response must never be reported as an unresolvable write"
    );
}

/// B13 frozen handoff fixture: the typed `MutableOutcome::Unknown` variant is reachable through
/// nothing but the public `lore_transport` re-exports -- no message parsing, no reclassification.
/// WP-120 links against this exact shape.
#[test]
fn a_dispatched_response_lost_outcome_is_frozen_as_typed_unknown_with_no_redispatch() {
    let unknown = OutcomeUnknown { command: "put" };
    let outcome: MutableOutcome<()> = MutableOutcome::Unknown(unknown.clone());

    match &outcome {
        MutableOutcome::Unknown(OutcomeUnknown { command }) => assert_eq!(*command, "put"),
        MutableOutcome::Applied(()) => {
            panic!("a dispatched-then-lost response must never resolve to Applied")
        }
    }
    assert!(outcome.is_unknown());
    assert_eq!(outcome.applied(), None);

    // The companion positive control: a normal success is free to report Applied -- this proves
    // the type discriminates, rather than every construction reading as unknown.
    let applied: MutableOutcome<()> = MutableOutcome::Applied(());
    assert!(!applied.is_unknown());
    assert_eq!(applied.applied(), Some(()));

    // No redispatch: nothing in this fixture calls back into the transport. The frozen value is
    // exactly what was constructed, still carrying the same command name.
    assert_eq!(unknown.command, "put");
}

/// `OutcomeUnknown` must be usable as a real `std::error::Error` (per the contract: Clone, Debug,
/// PartialEq, `std::error::Error`), since callers propagate it through `?` alongside other
/// transport errors.
#[test]
fn outcome_unknown_is_a_real_error_type() {
    fn assert_error<E: std::error::Error>(_: &E) {}

    let outcome = OutcomeUnknown { command: "put" };
    assert_error(&outcome);
    assert_eq!(outcome.clone(), outcome);
    assert_eq!(format!("{outcome:?}"), format!("{:?}", outcome.clone()));
}
