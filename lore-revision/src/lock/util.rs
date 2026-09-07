// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use crate::hash;
use crate::lock;
use crate::lore::BranchId;
use crate::lore_error;

pub const LOCK_BATCH_SIZE: usize = 100;

pub fn assemble_resource_for_path(path: &str, branch: BranchId) -> lock::LockResource {
    let hash = hash::hash_slice(path.as_bytes());
    let description = path.to_string();
    lock::LockResource {
        branch,
        hash,
        description,
    }
}

/// What a lock verb's error type has to be able to say for its batches to be given a set verdict
/// (CR-030, WP-120).
///
/// Both lock verbs dispatch one user request as several concurrent batches, and both then have to
/// decide one thing about the set as a whole: whether the answers settle what happened. The rule is
/// the transport's, restated here because it changes what each verb does next.
/// [`crate::dispatch::under_own_attempt`] draws the same line for the attempt journal — an
/// `OutcomeUnknown` means the answer was lost, so its record is deliberately left standing for a
/// later authoritative read, while any other error means the transport either held proof the
/// request never left or carried back the server's own refusal. The two must agree: journalling an
/// attempt as unresolved and then acting as though it decisively failed is exactly the
/// contradiction this trait exists to prevent.
///
/// One `matches!` per error type rather than a check at each caller, so a future non-decisive
/// variant has exactly one place per verb to be added.
pub(crate) trait BatchSetError: Sized {
    /// Whether this failure settles what happened to the request that produced it.
    fn is_decisive(&self) -> bool;

    /// The verb's own error for a set that failed with no per-batch error left to name.
    fn set_failed(message: &'static str) -> Self;
}

/// What a verb calls its batched dispatch, for the two strings [`classify_batch_set`] emits.
///
/// Passed rather than derived so the log line and the fallback message stay each verb's own words,
/// and a reader of a log or an error message still learns which verb produced it.
pub(crate) struct BatchSetLabels {
    /// Named in the "Failed to {verb} N batch(es) out of M" log line.
    pub verb: &'static str,
    /// Used when a set fails with no per-batch error to report — a shape nothing should be able to
    /// reach, and a message rather than a panic if it ever is.
    pub fallback: &'static str,
}

/// Why one set of batches did not complete, and whether the answer settles anything.
///
/// The second field is what a caller needs and a bare error cannot carry. Every action a verb may
/// take on top of a failed set — `release`'s escalation to an administrative takeover, `acquire`'s
/// rollback of a partial set — is a SECOND irreversible mutation, and it may only follow an answer
/// that decisively says the first one did not happen.
///
/// Note what this type does NOT carry, because it is easy to read a failed set as having produced
/// nothing: whatever the batches that DID answer produced is appended into the `succeeded`
/// accumulator the caller passed [`classify_batch_set`], on the failure path exactly as on the
/// success path. Those effects happened on the server whatever else went wrong, and a verb that
/// read only this value would be accounting for less than it caused. `acquire` reads that
/// accumulator to scope its rollback to what it actually took; `release` reads it to clear the
/// tokens of what the server confirmed released.
#[derive(Debug)]
pub(crate) struct SetFailure<E> {
    pub error: E,
    /// True only when every batch in the set answered decisively.
    ///
    /// The whole set, not the one batch that failed, because whatever a verb does next re-sends
    /// every resource in the set rather than only the ones a batch failed on. One unknown batch —
    /// or one batch task that never produced an answer at all — is therefore enough to make the set
    /// unsafe to act on again.
    pub decisive: bool,
}

/// What a set that did not fail produced.
///
/// Two fields rather than a bare count, because a partly successful set carries a failure the
/// caller still has to report. Dropping it made `acquire` tell a caller `Internal` for a batch the
/// server had refused with a reason.
#[derive(Debug)]
pub(crate) struct SetSuccess<E> {
    /// How many batches answered successfully. Fewer than `num_batches` means the set succeeded
    /// only in part, which is the difference `release` tolerates and `acquire` undoes.
    pub num_batch_success: usize,
    /// The first decisive failure a partly successful set carried, or `None` when every batch
    /// succeeded.
    pub first_decisive_failure: Option<E>,
}

/// Turn one set's per-batch outcomes into the set's verdict.
///
/// Shared by `acquire` and `release` rather than written once per verb. The two rules that are
/// easiest to get wrong live here, and neither is reachable through the live fixture, whose stub
/// answers one policy per RPC and so cannot make two batches of one set differ: an unknown batch
/// outranks a decisive refusal in the same set, and a lost batch task must not shadow a real lost
/// answer. A second copy of this would drift from the first silently, which is how `acquire` came
/// to count successes and failures while discarding the classified errors `release` was acting on.
///
/// `task_failure` describes batches whose task never produced an outcome — a panic or a
/// cancellation. Neither says whether the request reached the server, so it makes the set
/// non-decisive just as an unknown answer does.
///
/// On success a [`SetSuccess`] is returned rather than nothing, because a set can succeed
/// partially: `release` tolerates that and `acquire` undoes it, and only the caller knows which.
pub(crate) fn classify_batch_set<T, E: BatchSetError>(
    outcomes: Vec<Result<Vec<T>, E>>,
    task_failure: Option<E>,
    num_batches: usize,
    labels: &BatchSetLabels,
    succeeded: &mut Vec<T>,
) -> Result<SetSuccess<E>, SetFailure<E>> {
    let mut num_batch_success = 0usize;
    // Batches that produced no outcome at all. Counted from what is missing rather than tallied at
    // the join for two reasons. A second lost task is still reported even though the first one
    // already supplied the error value — and, found in review, a caller that loses an outcome
    // WITHOUT also setting `task_failure` still makes the set non-decisive here rather than
    // reaching the success arm on a set whose fate this function was never told. The guarantee
    // that a non-decisive set can never be acted on again must not rest on every caller's join
    // loop remembering to report its own `JoinError`.
    // Saturating because a caller that somehow produced MORE outcomes than it dispatched batches
    // must still be given a verdict rather than an underflow panic in release. In a debug build
    // that caller is a bug worth stopping on: the count it passed does not describe the set it
    // handed over, and every judgement below is derived from the two agreeing.
    debug_assert!(
        outcomes.len() <= num_batches,
        "a set of {num_batches} batch(es) produced {} outcome(s)",
        outcomes.len()
    );
    let num_batch_missing = num_batches.saturating_sub(outcomes.len());
    let mut num_batch_failed = num_batch_missing;
    let mut first_decisive_failure: Option<E> = None;
    let mut first_unknown_failure: Option<E> = None;

    // Appended as the outcomes are read, so the caller keeps what a partly successful set produced
    // even when the set as a whole fails. Those effects happened on the server whatever else went
    // wrong, and a verb that discarded them would be accounting for less than it caused.
    for outcome in outcomes {
        match outcome {
            Ok(mut results) => {
                succeeded.append(&mut results);
                num_batch_success += 1;
            }
            Err(error) => {
                num_batch_failed += 1;
                if error.is_decisive() {
                    first_decisive_failure = first_decisive_failure.or(Some(error));
                } else {
                    first_unknown_failure = first_unknown_failure.or(Some(error));
                }
            }
        }
    }

    if num_batch_failed > 0 {
        let verb = labels.verb;
        lore_error!("Failed to {verb} {num_batch_failed} batch(es) out of {num_batches}");
    }

    // Checked before the all-failed test, and ahead of any decisive failure the same set may also
    // carry. A set holding one unknown batch and one refusal is not a refused set: acting on the
    // refusal would re-send resources whose own mutation may already have happened.
    if first_unknown_failure.is_some() || task_failure.is_some() || num_batch_missing > 0 {
        return Err(SetFailure {
            // A real lost answer is preferred over a lost task, and the order matters. An
            // `OutcomeUnknown` names the attempt a reconciler has to look up. A lost task says
            // only that this client stopped watching, and no attempt id survives it — the one that
            // task minted died with it, already unresolved in the store, which is where a
            // reconciler finds it anyway. Minting a fresh `OutcomeUnknown` here to make the shape
            // tidier would name an attempt the server filed nothing under.
            error: first_unknown_failure
                .or(task_failure)
                .unwrap_or_else(|| E::set_failed(labels.fallback)),
            decisive: false,
        });
    }

    // Both halves are load-bearing. `num_batch_success == 0` alone would call a set of NO batches
    // a decisive failure, which is a lie about a set in which nothing was ever dispatched; neither
    // verb can reach that today, and neither should have to know it.
    if num_batch_failed > 0 && num_batch_success == 0 {
        return Err(SetFailure {
            error: first_decisive_failure.unwrap_or_else(|| E::set_failed(labels.fallback)),
            decisive: true,
        });
    }

    Ok(SetSuccess {
        num_batch_success,
        first_decisive_failure,
    })
}
