# Atomic resolved-merge finalization

**Date:** 2026-08-17
**Status:** Done and verified locally; nothing was pushed.
**Classification:** [CLIENT] (public `lore` client facade intended for upstream coordination).

## Summary

The WP4 review exposed that desktop conflict resolution tried to finalize a merge through the
ordinary exact-selection commit API with no selected paths. Lore now exposes a narrow
`finalize_resolved_merge` facade that admits and commits a resolved merge under one repository
write token. It validates authoritative staged merge state and rejects unresolved conflicts,
ordinary staged work, cherry-pick or revert state, and non-merge ride-along changes before commit.

## What changed

- `lore/src/revision.rs` adds the public async facade and contributor copyright while preserving
  Lore's callback and typed-error conventions.
- One `repository_call_write` token spans staged-state deserialize, diff and layer admission, and
  the lower commit call, closing the IPC preflight-to-commit race identified in review.
- Admission requires staged state, `state_staged.is_merge()`, a nonzero other parent, merge-diff
  evidence, at least one resolved conflict, no unresolved conflict, and no unrelated diff or layer
  residue.
- Existing `MergeError` variants and forwarded lower-layer failures preserve stable error codes:
  nothing staged, invalid arguments, and unresolved conflict remain distinct.
- `lore/tests/merge_finalize_transaction.rs` covers ordinary, cherry-pick, revert, unresolved,
  file-ride-along, and layer-residue refusal without moving anchors. It also covers manual, mine,
  and theirs resolution success, two-parent publication, cleanup, double-finalize refusal, callback
  order, and deterministic write-token continuity.

## Why now

Exact-selection is correct for ordinary commits but cannot represent the whole staged merge that
Lore itself owns. Desktop WP4 needed one transaction-shaped merge authority instead of a separate
check followed by a commit that another writer could invalidate.

## Reviewer findings

- Applied: atomic facade instead of an IPC-only preflight, authoritative `is_merge()` admission,
  typed error forwarding, contributor copyright, and transaction-level regressions.
- The final Lore reviewer reported no remaining correctness, idiom, or coverage finding in the
  implemented boundary.

## Verification

- Focused resolved-merge transaction suite: 6 passed, 0 failed.
- `cargo check -p lore --tests -j 4` and the scoped rustfmt check passed.
- Tests use `lore_spawn!` and deterministic block observation; production code adds no
  `unwrap`, `expect`, raw Tokio spawn, wire change, or on-disk format change.

## Upstream and residual boundary

This is a high-risk CLIENT public-API change. Open the upstream issue and, if maintainers require
it, an LEP before upstreaming; preserve DCO sign-off and disclose AI assistance in the human-written
PR description. Explicit linked-repository residue is not automated because it needs a live remote
fixture, so that case remains remote-backed manual or upstream follow-up coverage.
