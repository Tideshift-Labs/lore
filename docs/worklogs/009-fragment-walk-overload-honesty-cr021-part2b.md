# Report an overloaded store from the fragment walk (CR-021 Part 2b)

**Date:** 2026-07-25
**Status:** Done (fork-side, merged locally into `tideshift/main`; not pushed or submitted upstream)
**Classification:** NOT cleanly [SERVER] — unlike Parts 1 and 2a (`lore-aws`, server-only), this
touches `lore-revision`, which ships in the `lore` CLI. See "Client-safety verification" below for
why it was shippable anyway.

## Summary

`collect_new_addresses` decides which fragments a caller must transfer or verify, and it swallowed
every error from three separate reads. Two of those swallows lose data, not just precision: when a
fragmented payload's content or a child subtree can't be read, its children are dropped from the
result entirely rather than reported as new. On the push path (`branch_push.rs`) that result is
exactly the set `verify_fragments` existence-checks, so a fragment dropped by either swallow is
never checked at all — under a throttled store, a push can be accepted carrying a reference to
content the server never confirmed it has. Fix: only `SlowDown` now propagates out of the walk;
every other error keeps its long-standing behavior unchanged.

## What changed

- `lore-revision/src/state.rs`: the fragment-walk task's return type went
  `Option<Vec<Address>>` → `Result<Option<Vec<Address>>, StateError>`. Uses the
  `Err(X::SlowDown(traced)) => Err(StateError::SlowDown(traced))` idiom already established at
  `state.rs:585`, preserving the trace. Both join sites take a second `?`.
- `lore-server/src/grpc/handlers/branch_push.rs`: added the missing `.filter_slow_down()?` on the
  `verify_fragments` call site (reviewer finding, below).
- `lore-revision/tests/state.rs`: new `FaultInjectingStore` fixture wrapping a real
  `LocalImmutableStore`, plus tests for SlowDown propagation from `query`, the
  conservative-fallback regression guard for non-SlowDown errors, genuine-absence-is-unaffected,
  and swallow-#3 propagation.

## The reframing that justified doing this at all

Both the CR and INV-AP describe the `query()` swallow (fail-safe: an unreadable address is
reported as new, costing a redundant transfer) as *the* throttle-honesty gap here. Reading the code
showed that swallow is the safe one. The two that matter are the `load_raw()` swallow on a
fragmented payload and the recursion-error swallow on a child subtree — both fail-open, both drop
data the push path never re-checks. That's what made 2b worth doing on its own, separately from
Part 1's `load_metadata` fix.

Fix is deliberately narrow: **only `SlowDown` propagates**; everything else — including the two
fail-open drops for non-throttle errors — keeps its exact prior behavior. `lore-revision` ships in
the CLI we distribute, so a broad change reaches users directly; narrowing keeps this reviewable as
one new failure mode, not a rewrite of how the walk handles failure.

**Known, deliberate residual:** a non-overload failure in either fail-open swallow still silently
drops a subtree. The integrity gap is closed for throttling specifically, not in general.

## Reviewer finding

`lore-reviewer` found `verify_fragments` was the one `StateError` call site in `branch_push.rs`
without `.filter_slow_down()?` (siblings at :329, :378, :388, :486, :537, :565; helper at
`lore-server/src/grpc/mod.rs:446-459`). Left as-is, the new `SlowDown` would have landed in the
fallback `Status::internal(...)` — un-retried, wrong gRPC code — while the `exist_batch` loop 60
lines below already answers `Status::resource_exhausted("Slow down")` for the same condition.
Unfixed, 2b would have traded a silent-corruption bug for an un-retried internal error. Applied.

## Client-safety verification

This is the load-bearing check for shipping a `lore-revision` change:

- Production CLI reachability is nil: the only local-store `SlowDown` emitters
  (`lore-storage/src/local/immutable_store.rs:3184,3246`) are behind
  `#[cfg(feature = "failure_generator")]`, absent from every `default` feature list. The only
  other emitters are `CompositeStore` (constructed solely at `lore-server/src/server.rs:1212`) and
  `GrpcReplica` — both server-only. Confirmed the repo's sole `--all-features` use
  (`.pre-commit-config.yaml:24`, `cargo-deny` for licenses) doesn't build a binary.
- All four callers of `collect_new_addresses` are safe, including `restore.rs:481` (flagged
  unverified going in): every one feeds the result into a *push* of missing fragments (restore's
  own comment: "Check missing fragments on server"). None reads past unavailable fragments as a
  legitimate outcome, so erroring is strictly safer than pushing a truncated set.

## Coverage gap, recorded honestly

Swallow #2 (`load_raw()` on a fragmented payload) has no direct test and isn't reachable with a
local-only fixture: `lore_storage::read::load_fragment` always attempts a remote fallback, so
against the standard `Err(NoRemote)` test repository that fallback's error supersedes the injected
local `SlowDown` before the arm under test is reached. The branch is real in production — reachable
when the combined local+remote answer is itself `SlowDown` — but exercising it needs a mock
storage session; judged disproportionate for this chunk. Reasoned about, not pinned.

## Interaction with Parts 1 and 2a

Part 1 (worklog 007) made `load_metadata`/`query` honest about throttling. 2a (worklog 008) added
SDK-level retry, narrowing how often a throttle reaches this code at all. 2b closes the correctness
gap for whatever throttling still gets through — a push can no longer silently omit fragments the
server hasn't confirmed it has, when the cause is store overload.

## Why now

Traced by `../lorehub/docs/investigations/inv-ap-large-push-dynamo-fanout-timeout.md`; sequenced by
`../lorehub/docs/adr-00022-caching-strategy-and-sequencing.md`. Spec:
`../lorehub/docs/lore-change-requests/cr-021-throttle-honesty-and-fragment-fanout-backoff.md`
(closes Part 2b; Part 3 — batching the tree-walk reads — not started).

## Tests and gates

`lore-test-specialist` owned the tests. Final on merged `tideshift/main`:
`cargo test -p lore-revision --test state` — 40 passed / 0 failed. `cargo test -p lore-server --lib
grpc::handlers::branch_push::tests` — 5 passed / 0 failed (includes
`verify_fragments_maps_slow_down_to_resource_exhausted`, pinning the reviewer's fix).
`cargo +nightly fmt --all` clean. `cargo clippy -p lore-revision -p lore-server --all-targets --
-D warnings --no-deps` clean. The full `lore-revision` suite was not run (prohibitively slow on
this rig); scoped to the touched test file.

## Follow-ups

- CR-021 Part 3 (batching the tree-walk reads) remains open, tracked in the CR spec.
- The non-throttle fail-open residual in swallows #2/#3 is unaddressed by design; revisit only if a
  future incident traces back to it.
- Swallow #2's SlowDown path is untested; would need a mock storage session to reach.

## Status: CR-021

Parts 1, 2a, and 2b are done. Part 3 is not started.
