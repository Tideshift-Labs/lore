# Rebase `tideshift/main` onto latest upstream

**Date:** 2026-08-26
**Status:** Done, verified, and published.
**Classification:** Mixed [SERVER]/[CLIENT]; this refresh changes the base beneath both paths.

## Summary

Rebased the long-running `tideshift/main` fork from upstream Lore `52b8b774` onto
`upstream/main` at `7e785450`. All 91 existing fork commits were preserved and replayed in order,
then signed integration fix `7cdc36b` repaired the remaining compile and test fallout from the
new upstream APIs. The resulting branch contains upstream as an ancestor and has 92 commits on top:
the preserved fork series plus the integration repair.

## What changed

- Advanced the clean upstream base by 25 commits, from `52b8b774` to `7e785450`, while retaining
  `tideshift/main` as the long-running fork branch.
- Preserved all 91 fork commits. A range-diff mapped the complete old series onto the rebased one;
  87 patches were identical and four changed only where the new upstream base overlapped them.
- Reconciled upstream's supplied-credential isolation with the fork's stored-token refresh path.
  Store-resolved credentials can refresh, while caller-supplied tokens remain isolated and are
  passed through for server-side validation.
- Reconciled upstream storage contract and path-shape changes with the fork's retention and
  Postgres behavior, and retained the fork's explicit non-incremental test profile alongside
  upstream's development debug profile.
- Added signed follow-up `7cdc36b` to port exact-selection modified-time clearing to the upstream
  `RelativePath` API, restore the composed authentication test module, disambiguate the updated
  `rand` lockfile dependency, and record the new stage-topology regression coverage.

## Why now

The prior upstream refresh had been completed locally but not published, so the local rebased tip
and `origin/tideshift/main` diverged and a normal push was correctly rejected as non-fast-forward.
Meanwhile, upstream advanced another 25 commits. Rebasing again establishes the requested current
upstream foundation without replacing the fork's long-running branch model.

## Verification

- `cargo +nightly fmt --all -- --check` passed.
- Workspace all-target compilation passed with four jobs.
- Workspace all-target, no-dependency Clippy passed with warnings denied.
- Workspace tests passed with zero failures; the harness listed 3,431 tests.
- Targeted credential and transport authentication suites passed.
- Targeted exact-selection stage-topology, stage-lifecycle, and state suites passed.
- The range-diff accounted for every commit in the 91-commit pre-rebase fork series.

## Publication

The old remote tip `020e6bde` remains recoverable as
`backup/tideshift-main-pre-upstream-20260826`. After a fresh fetch confirmed that exact tip was
still current, `tideshift/main` was updated to `7cdc36b` with an exact `--force-with-lease` bound to
`020e6bde`.
