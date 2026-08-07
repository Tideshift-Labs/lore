# Remote-proven sync repairs named-branch bookkeeping

**Date:** 2026-08-06
**Status:** Done. Focused regressions, formatting, and clippy are green.
**Classification:** [CLIENT]. This changes local sync behavior in `lore-revision` and the in-process
Rust facade, so upstream acceptance remains the release gate for general client distribution.

## Summary

An explicit revision sync can now carry narrowly scoped proof that its target came from a verified
remote tip on the current branch. Lore uses that proof to advance stale named-branch bookkeeping
when the target is a linear descendant, including when the working tree already has that revision.
Ordinary explicit revision syncs retain their local-target merge semantics and cannot move branch
latest backward, across branches, or through a merge target.

## What changed

- `lore-revision/src/revision/sync.rs` adds `SyncOptions.revision_is_remote` and computes whether a
  proven target safely advances the current branch before changing `LATEST` or last-sync metadata.
- The same bookkeeping update runs on the early no-op return, repairing repositories whose current
  anchor had advanced while the named branch latest pointer remained stale.
- The ancestry check requires the target metadata to name the current branch, rejects merge
  revisions, and updates only for a first-parent linear advance. Older local history remains the
  authority when the target does not advance it.
- `lore/src/revision.rs` exposes `sync_verified_remote` as a Rust-only in-process companion to
  `sync`. `LoreRevisionSyncArgs`, the C ABI, CLI behavior, and service serialization stay unchanged.
- `lore-revision/tests/sync.rs` replaces the single explicit-sync case with focused coverage for
  local backward sync, no-op repair, older proven targets, cross-branch targets, and forward
  bookkeeping advances.

## Reviewer findings

Review identified two correctness boundaries before the final pass: the remote could advance again
after preflight, and adding provenance to public sync args would break ABI consumers. The landed
ancestry check accepts the pinned target only when it still advances local history, while the
Rust-only facade avoids the ABI change. Final review was clean; nothing was deferred.

## Verification

- Focused `lore-revision` sync regressions: **5/5 passed**.
- `cargo +nightly fmt --all`: clean.
- Clippy with warnings denied and dependencies excluded: clean.

## What this unblocks

The desktop's authenticated auto-sync path can pin the exact revision it preflighted without leaving
named-branch divergence stale or granting the same authority to generic explicit revision callers.

## Why now

Desktop auto-sync exposed a split-brain local state: the current anchor matched the remote revision,
but the named branch pointer still reported one revision behind. A later Sync returned early as a
working-tree no-op and could never repair that metadata. The provenance seam fixes the local state
without changing exact-target sync semantics for existing callers.
