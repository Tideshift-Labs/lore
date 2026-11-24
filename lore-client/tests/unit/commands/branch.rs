// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-120): routing of `lore branch push`.
//!
//! The CLI handler is a thin function over a blocking runtime and a stdout formatter, so its
//! routing is pinned from its source, as a trace of the one call it makes. The behaviour behind
//! that call is proven where it runs: `lore/tests/lock_refusal.rs`
//! (`the_cli_push_entry_runs_under_the_managed_runner`) drives
//! `push_managed_refusing_others_locks` against a live fixture and asserts the managed journal.

/// The source of the CLI's branch commands.
const SOURCE: &str = include_str!("../../../src/cli/commands/branch.rs");

/// The text of `handle_branch_push`, from its signature to its closing brace.
fn push_handler() -> &'static str {
    let start = SOURCE
        .find("pub fn handle_branch_push(")
        .expect("the push handler must exist");
    let rest = &SOURCE[start..];
    let end = rest
        .find("\n}\n")
        .expect("the push handler must end at a top-level brace");
    &rest[..end]
}

/// `lore branch push` reaches the engine only through the managed, lock-refusing entry, with no
/// observer and the lock check on unless `--ignore-locks` is given. That entry is
/// `push_managed_local`, which runs the push under a `ManagedPushRunner`.
#[test]
fn branch_push_routes_through_the_managed_lock_refusing_entry() {
    let handler = push_handler();
    let call = handler
        .find("branch::push_managed_refusing_others_locks(")
        .expect("the CLI push must call push_managed_refusing_others_locks");
    let arguments = &handler[call..];
    assert!(
        arguments.contains("None,") && arguments.contains("!args.ignore_locks"),
        "no observer, and the lock check follows --ignore-locks: {arguments}"
    );
}

/// No other push entry is reachable from the handler: an unmanaged `branch::push`, the journalled
/// `push_with_attempt_store`, or the plain `push_managed` (which never refuses on locks) would each
/// skip part of what the managed, lock-refusing entry does.
#[test]
fn branch_push_calls_no_other_push_entry() {
    let handler = push_handler();
    for other in [
        "branch::push(",
        "branch::push_with_attempt_store(",
        "branch::push_journalled(",
        "branch::push_managed(",
    ] {
        assert!(
            !handler.contains(other),
            "the CLI push must not call {other}"
        );
    }
}
