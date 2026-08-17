# Propagate file-metadata task errors

**Date:** 2026-08-16
**Status:** Done; upstream-oriented commit `ab363af7c7df88f037762899a802394a3b6c56df`,
merged into local `tideshift/main` as `d617db8866c90d7a9487738f37dd5d9e019bf919`.
Neither commit was pushed, and no upstream PR was opened.
**Classification:** [CLIENT] (`lore-revision` ships in the CLI and links into
`lorehub-desktop`).

## Summary

File metadata tasks could fail internally while the legacy setter returned success. The setter
now drains every spawned task, gives an outer `JoinError` precedence, and otherwise returns the
inner `SetError` with the lowest original input index. A failed batch publishes neither a staged
metadata anchor nor a success metadata event.

## What changed

- `lore-revision/src/metadata/set.rs` associates each spawned task with its caller input index,
  drains the complete task set, and selects errors deterministically before publication.
- `lore-revision/tests/metadata_set.rs` adds a permanent seven-row failure and compatibility
  matrix. It covers missing binary input, mixed successful and failing siblings, two ordered
  failures, event suppression, successful string and binary metadata, duplicate compatibility,
  revision metadata failure, and `clear_file`.
- The legacy duplicate-key policy remains last-write-wins. Successful sibling tasks may still
  leave unreachable immutable blobs, so this is publication atomicity rather than rollback.

## Why now

Exact-selection commit v1 needs metadata failure to reach the caller before its transaction can
admit an exact staged metadata hash. The defect existed on the shared active/upstream source blob.
See [CR-024](../../../lorehub/docs/lore-change-requests/cr-024-file-metadata-task-errors.md) and
[WP2](../../../lorehub-desktop/docs/work-packages/wp-exact-selection-lore-metadata-errors.md).

## What this unblocks

WP3 can add the exact-selection transaction and its required exact staged-hash admission without
building on a file metadata setter that reports failed work as successful. WP3 remains required.

## Reviewer findings

The first `lore-reviewer` pass approved production behavior and requested contributor attribution,
an event-enabled failure assertion, and stronger deterministic timing proof. All three were
applied. The second pass approved the change with no blocker. Natural `JoinError` and more-than-1000
task throttle paths remain source-covered after explicit triage.

## Verification

- Unchanged focused baseline: 0 passed / 1 failed because the setter returned `Ok`.
- Final file-metadata matrix: 7 passed / 0 failed.
- `lore` metadata: 2 passed / 0 failed.
- `lore-revision` commit: 3 passed / 0 failed.
- Existing `lore-revision` metadata: 9 passed / 0 failed.
- Scoped `lore-revision` Clippy with warnings denied: clean.
- `cargo +nightly fmt --all -- --check`: clean.
- Workspace Clippy did not complete cleanly; it reached only the documented unrelated
  `lore-client/src/cli/commands/branch.rs:1369` lint.

## Contribution posture

Both Lore commits carry DCO sign-off and AI-assistance disclosure. The isolated contribution
branch was `cr-024-file-metadata-task-errors`; pushing it or opening an upstream PR remains a
separate authorized action.
