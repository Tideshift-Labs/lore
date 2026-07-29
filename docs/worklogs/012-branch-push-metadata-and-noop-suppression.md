# Branch-push metadata and no-op side-effect suppression

**Date:** 2026-07-29
**Status:** Done (fork-side, uncommitted at time of writing)
**Classification:** [SERVER]. The change is confined to loreserver push handling and its tests.

## Summary

Branch pushes now expose whether they actually advanced the branch, and only advancing pushes emit
the branch-pushed notification, post-push hook, and `num_branches_pushed` metric. This gives
Lorehub's teammate-push notification pipeline trustworthy revision metadata without producing a
second event when a client harmlessly re-pushes the current head.

## What changed

- `lore-server/src/grpc/handlers/branch_push.rs` and
  `lore-server/src/grpc/revision/v1/branch_push.rs` carry `PushResult.advanced` through both server
  push paths.
- A no-op re-push remains a successful RPC, but no longer publishes `branch_pushed`, dispatches a
  `HookPoint::BranchPush` post-hook, or increments the pushed-branch counter.
- Handler regressions observe the detached notification and hook tasks and assert that one
  advancing push followed by one no-op push produces exactly one of each side effect.
- `lore-server/src/hooks/mod.rs` and `lore-server/src/plugins/mod.rs` expose the test-only
  construction seams used by those handler-level regressions.
- The fork testing guide records the focused coverage and the in-memory metric-exporter approach.

## Why now

The cross-repo teammate-push notification feature consumes Lore's branch-push metadata as its
durable source event. A successful no-op RPC is valid client behavior, but treating it as a new
push would duplicate inbox rows, live badges, and desktop toasts downstream.

## What this unblocks

Lorehub can treat every emitted `branch_pushed` event as a real branch advance and fan it out
without adding an unreliable downstream guess about whether the revision changed.

## Verification

- Focused handler tiers: 6 tests in `grpc::handlers::branch_push::tests` and 11 tests in
  `grpc::revision::v1::branch_push::test`, all green.
- The full Lore unit suites, formatting, and clippy gates were reported green.
- Cross-client push liveness was exercised downstream: 1/1 acceptance spec and 34/34 e2e harness
  unit tests green.
