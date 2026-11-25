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
