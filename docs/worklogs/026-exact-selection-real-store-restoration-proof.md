# Exact-selection real-store restoration proof

**Date:** 2026-08-17
**Status:** Done and verified locally; nothing was pushed.
**Classification:** [CLIENT] (`lore-revision` is client-path code intended for upstreaming).

## Summary

The final WP1/WP2/WP3 review follow-up replaces the remaining writer-closure-only evidence for
exact-selection compensation with deterministic fault injection around a real, tempdir-backed
`LocalMutableStore`. The tests drive the production finalizer and anchor store/load functions,
then flush, drop, reopen, and reload the store to prove that `anchors_restored` reports the tested
durable outcome. This is verification only; production behavior did not change.

## What changed

- `lore-revision/src/exact_selection.rs` adds a test-only `MutableStore` wrapper which delegates
  every operation to `LocalMutableStore` except explicitly numbered failing `store` calls.
- The success case injects a one-shot publication failure at call `[2]`. Compensation succeeds,
  the error reports `anchors_restored: true`, and branch-latest, current, and staged all reload as
  their original values after an explicit flush and complete store reopen.
- The failure case injects failures at calls `[2, 3, 4, 5]`: the publication write and all three
  retries that restore branch-latest. The error honestly reports `anchors_restored: false`, while
  the reopened real store exposes the expected partial state.
- Both cases traverse the production exact-selection finalizer plus the real branch/current/staged
  store and load paths. The wrapper controls faults at the `MutableStore` boundary rather than
  replacing those paths with an in-memory writer closure.
- `docs/testing-guide.md` records the fixture topology, numbered fault plans, and durability
  assertions so future CLIENT changes can preserve the same evidence.

## Why now

Fable5's final review correctly identified that compensation was proven only through the thin
writer closure. WP4's user-facing recovery UX may trust `anchorsRestored: true`, so that signal
needed evidence at the real mutable-store boundary before WP4 close-out. The new fixture closes
that escalation trigger without relying on flaky platform-specific disk-full, permissions, or
antivirus behavior.

## Verification and reviewer finding

- New real-store restoration tests: 2/2.
- Exact-selection units: 15/15; commit compensation helpers: 4/4.
- Public exact-selection transaction: 15 passed plus 1 intentionally ignored descriptive test.
- `cargo +nightly fmt --all` and the formatting diff check passed.
- `lore-revision` all-target Clippy passed with warnings denied and dependencies excluded.
- Applied: the writer-closure-only coverage gap now has production-finalizer, real-store, and
  reopen evidence for both truthful restoration outcomes.

## Residual limit

The fixture injects deterministic failures at the `MutableStore::store` boundary and proves a
successful flush/reopen round trip. It does not simulate an operating-system-level flush failure,
disk exhaustion, permissions change, or antivirus lock; those remain environment-dependent fault
classes rather than claims made by this test.
