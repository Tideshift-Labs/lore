# Treat empty histories as a shared root

**Date:** 2026-08-13
**Status:** Done; committed to `tideshift/main` as `d249e4d`.
**Classification:** [CLIENT] (`lore-revision` ships in the CLI and links into
`lorehub-desktop`).

## Summary

`find_branch_point(zero, zero)` skipped its history-walk loop and returned "failed to find a
branch point". That made a successful clone of a brand-new empty remote fail its first auto-sync
ahead/behind check and appear Diverged. Two empty histories now share the zero hash as their branch
point and return empty left and right histories.

## What changed

- `lore-revision/src/history.rs` returns `(zero, [], [])` before walking history when both heads
  are zero.
- `lore-revision/tests/revision.rs` adds a focused async regression test for the zero/zero case.
- Both edited files carry the contributor SPDX copyright line.
- The test runs inside `LORE_CONTEXT.scope`, matching Lore's execution-context contract.

## Why now

Staging desktop cloned a newly created empty remote successfully, then its auto-sync dry-run failed
while reconciling branch history. The resulting error was presented as Diverged even though neither
side had a revision. The zero/zero regression reproduced red before the fix and green after it.

## Reviewer findings

`lore-reviewer` classified the fix [CLIENT] and found the correctness argument clear. Its two
contributor-convention findings were applied: add the SPDX copyright lines and wrap the async test
with `LORE_CONTEXT`.

## Verification

- Scoped `lore-revision`: 632 passed / 0 failed / 1 ignored.
- Scoped formatting and Clippy: clean.
- Later full-fork audit at current HEAD `8de9df0`: fmt, check, Clippy, and release build clean.
- Supplemental Rust workspace run excluding the compiler-wording snapshot: 2,566 passed / 0
  failed / 45 ignored; `lore-error-set` library: 23 passed / 0 failed.
- Full Python suite: 877 collected; 832 passed / 42 skipped / 2 xfailed / 1 failed / 0 errors.
  The sole failure is the known Windows extended-path directory-move case.
- Canonical Rust workspace test reached 446 passes and remained red only on the known rustc
  trybuild diagnostic-wording mismatch.
- Opt-in MinIO and Dynamo integration features were not run.

## Notes

HEAD advanced after this bugfix because `8de9df0` separately changed development and test TOML
configuration. That commit and its changes are not part of this chunk.

