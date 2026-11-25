// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the exit status of `lore commit --exact-selection`.
//!
//! The handler is a thin function over a blocking runtime and the output formatter, so its
//! exit-code mapping is pinned from its source. The behaviour behind it is proven where it runs:
//! `lore/tests/lock_refusal.rs` (`an_exact_selection_commit_over_another_users_lock_is_refused`)
//! asserts the error's status is `LockNotOwned` (45), and
//! `lore-revision/tests/unit/exact_selection.rs` pins the error type's code and message.

/// The source of the CLI's revision commands.
const SOURCE: &str = include_str!("../../../src/cli/commands/revision.rs");

/// The text of `handle_revision_commit_exact_selection`, from its signature to its closing brace.
fn exact_selection_handler() -> &'static str {
    let start = SOURCE
        .find("fn handle_revision_commit_exact_selection(")
        .expect("the exact-selection handler must exist");
    let rest = &SOURCE[start..];
    let end = rest
        .find("\n}\n")
        .expect("the exact-selection handler must end at a top-level brace");
    &rest[..end]
}

/// A refusal exits with the error's own status code, so a lock refusal is `LockNotOwned` (45).
/// `translated()` would collapse it to `InvalidArguments` (3), because `LoreError` has no
/// `LockNotOwned` member.
#[test]
fn exact_selection_exit_code_is_the_error_status_not_the_translated_one() {
    let handler = exact_selection_handler();
    assert!(
        handler.contains("error.code() as u8"),
        "the refusal must exit with the error's status code: {handler}"
    );
    assert!(
        !handler.contains("error.translated()"),
        "the refusal must not exit with the translated LoreError: {handler}"
    );
}

/// The text of `handle_revision_commit`, from its signature to its closing brace.
fn commit_handler() -> &'static str {
    let start = SOURCE
        .find("pub fn handle_revision_commit(")
        .expect("the commit handler must exist");
    let rest = &SOURCE[start..];
    let end = rest
        .find("\n}\n")
        .expect("the commit handler must end at a top-level brace");
    &rest[..end]
}

/// The library's lock refusal is neutral; the CLI adds the override hint. The staged commit
/// handler prints it for the lock status, keyed on whether the check was on (`--ignore-locks`
/// off).
#[test]
fn commit_handler_prints_the_ignore_locks_hint() {
    let handler = commit_handler();
    assert!(
        handler.contains("print_ignore_locks_hint(commit_result, !args.ignore_locks)"),
        "the commit handler must print the hint when the check was on: {handler}"
    );
}

/// The exact-selection handler prints the hint (plain message) for a `LockNotOwned` kind.
#[test]
fn exact_selection_handler_prints_the_hint_for_a_lock_refusal() {
    let handler = exact_selection_handler();
    assert!(
        handler.contains("ExactSelectionErrorKind::LockNotOwned"),
        "the handler must recognize the LockNotOwned kind: {handler}"
    );
    assert!(
        handler.contains("eprintln!(\"{IGNORE_LOCKS_HINT}\")"),
        "the handler must print the hint: {handler}"
    );
}

/// The hint text and the status it follows are pinned.
#[test]
fn the_hint_text_and_lock_status_are_pinned() {
    assert!(
        SOURCE.contains(
            "pub(crate) const IGNORE_LOCKS_HINT: &str = \"Pass --ignore-locks to go ahead anyway.\";"
        ),
        "the hint text changed"
    );
    assert!(
        SOURCE.contains("pub(crate) const LOCK_NOT_OWNED_STATUS: u8 = 45;"),
        "the lock status must be 45"
    );
    assert!(
        SOURCE.contains("if checked && status == LOCK_NOT_OWNED_STATUS && !config().json {"),
        "the hint prints only when the check was on, the status is the lock refusal, and the \
         output is not --json"
    );
}
