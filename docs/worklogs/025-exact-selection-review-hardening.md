# Exact-selection review hardening

**Date:** 2026-08-17
**Status:** Done and verified locally; nothing was pushed.
**Classification:** [CLIENT] (`lore-revision` is client-path code intended for upstreaming).

## Summary

The WP1/WP2/WP3 review pass tightened the exact-selection transaction at its authority,
publication, input, and performance boundaries. `Unchanged` metadata now inherits only committed
state, availability probing opens rather than reads a whole file, publication failures expose
whether compensation restored every anchor, and caller mistakes map to stable invalid-argument
codes. The final Lore reviewer pass found no remaining issue.

## What changed

- `lore-revision/src/exact_selection.rs` inherits `Unchanged` metadata from `state_current`, rejects
  Windows drive-relative/rooted paths, and rejects duplicate normalized paths before binary
  metadata source I/O.
- Selected-file membership and content checks now use sorted binary searches, replacing repeated
  linear scans with O(n log n) lookup behavior across the batch.
- `lore-revision/src/commit.rs` uses an open-only pre-fragmentation probe instead of reading and
  discarding the full working file.
- Publication and compensation now return typed `PublicationFailure { anchorsRestored, reason }`.
  Generic pre-publication internals remain distinct, and the public JSON shape plus internal error
  code are pinned without parsing display text.
- Generated/semantic selection, metadata, digest, and source mismatches now consistently map to
  `InvalidArguments`; publication failures remain `Internal`.
- The production compensation helper is exercised directly for each anchor-write failure and for
  failed restoration, preserving the causal source chain in the resulting reason.
- `md-5` moved to the workspace dependency at 0.11, with explicit hex encoding compatible with the
  linked desktop workspace.
- `lore-revision/tests/exact_selection_transaction.rs` adds committed-vs-abandoned-staged metadata,
  duplicate-before-I/O, Windows path, mismatch-code, and publication-state regressions.

## Why now

The first implementation in CR-025 established the atomic exact-selection seam, but the close-out
review found correctness and contract gaps that callers could not safely infer around metadata
inheritance and partial publication. These fixes complete WP3 while preserving the WP1 stage
topology and WP2 metadata-error prerequisites. See
[CR-025](../../../lorehub/docs/lore-change-requests/cr-025-atomic-exact-selection-client-transaction.md)
and [ADR-00024](../../../lorehub/docs/adr-00024-atomic-exact-selection-client-transaction.md).

## Verification and reviewer findings

- Exact-selection units: 13/13; publication compensation: 4/4; transaction integration: 15/15,
  plus one intentionally ignored descriptive measurement; public facade lifecycle: 1/1.
- Stage topology 2/2, metadata-set 7/7, stage 7/7, commit 3/3, revision metadata 9/9, and `lore`
  metadata 2/2 remained green.
- Affected and workspace all-target Clippy passed with warnings denied; nightly fmt passed.
- Reviewer follow-ups replaced synthetic helper-only assertions with the actual compensation and
  finalize-mapping seams, and retained both publication and restoration causes.
- Final reviewer pass reported no remaining actionable correctness, naming, or coverage finding.
  Non-blocking upstream tripwires and residual verification limits are recorded in CR-023 through
  CR-025 rather than mixed into this CLIENT follow-up.
