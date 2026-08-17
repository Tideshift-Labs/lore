# Atomic exact-selection CLIENT transaction

**Date:** 2026-08-16
**Status:** Done and verified. Upstream-oriented `d7d2b67` was merged locally into
`tideshift/main` as `3d9909c`; not pushed and no upstream PR opened.
**Classification:** [CLIENT] (upstream-intended `lore-revision` and `lore` client code).

## Summary

Lore now offers one typed `commit_exact_selection` operation that holds one CLIENT write token
and token-bearing repository context from staged-state repair through action, semantic, metadata,
immutable-byte MD5 admission, publication, tracker drainage, and cleanup. A successful return
therefore proves the revision contains the caller's exact normalized selection; rejected
admission preserves all published anchors.

## What changed

- `lore-revision/src/exact_selection.rs` defines the bounded request/result/error contract and the
  transaction: repair staged state from current, stage selected paths, apply exact metadata,
  inspect generated actions, project effective semantics, and reread immutable Add/Modify bytes
  for lowercase RFC MD5 admission.
- `lore-revision/src/commit.rs`, `branch.rs`, and `file/stage.rs` expose the internal no-publication
  seams needed to keep admission inside one token boundary. Partial mutable publication restores
  the original branch-latest, current, and staged anchors before returning a typed failure.
- `lore/src/call.rs` and `lore/src/revision.rs` add the minimum structured facade while retaining
  one correlation id and callback lifecycle.
- `lore-revision/tests/exact_selection_transaction.rs` and
  `lore/tests/exact_selection_transaction.rs` pin mixed Add/Modify/Delete and rename behavior,
  metadata membership, semantic and digest rejection, immutable capture, writer exclusion,
  exact reload/materialization, anchor preservation, and facade token release.
- Requests are bounded before mutation. Binary metadata uses a single-open asynchronous
  `remaining + 1` read, enforcing both per-source and aggregate limits without unbounded growth.

## Why now

Desktop exact-selection commit v1 could not safely compose repair, stage, metadata, status, and
commit calls across separate CLIENT critical sections. WP1 and WP2 supplied the stage-topology and
metadata-error prerequisites; this WP3 transaction closes the remaining authority gap. See
[CR-025](../../../lorehub/docs/lore-change-requests/cr-025-atomic-exact-selection-client-transaction.md),
[ADR-00024](../../../lorehub/docs/adr-00024-atomic-exact-selection-client-transaction.md), and the
[WP3 spec](../../../lorehub-desktop/docs/work-packages/wp-exact-selection-lore-transaction.md).

## Verification

- Exact-selection units: 12 passed; authoritative publication restoration: 3 passed.
- Exact-selection integration: 10 passed, plus 1 explicitly ignored descriptive performance test;
  `lore` facade: 1 passed.
- Named regressions remained green: multi-worker topology 2/2, stage 7/7, file metadata 7/7,
  commit 3/3, revision metadata 9/9, and `lore` metadata 2/2.
- Affected-crate Clippy and workspace Clippy both passed with warnings denied; nightly fmt passed.
- Final cached same-process measurements were 13,469 us for 100 actor-sized files and 170,515 us
  for 1,000. They are descriptive only because fixtures and immutable content were warm in the
  same process.

## Reviewer findings and follow-up

Final `lore-reviewer` and `tauri-backend-reviewer` passes were clean. No findings remain deferred
from WP3. WP4 desktop/Unreal integration is unblocked; no other follow-up or rollout is implied.
