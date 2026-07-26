# Throttle honesty in `load_metadata` (CR-021 Part 1)

**Date:** 2026-07-25
**Status:** Done (fork-side, merged locally into `tideshift/main`; not pushed or submitted upstream)
**Classification:** [SERVER]

## Summary

`AwsImmutableStore::load_metadata` mapped every non-timeout DynamoDB SDK error onto
`AddressNotFound`, so a storage-tier throttle on `GetItem` was indistinguishable from genuine
content absence. A caller can't retry an integrity-shaped error, and an operator sees "missing
content" for what is actually a capacity problem. This chunk lands only Part 1 of CR-021: honest
error classification at the `load_metadata`/`query` boundary. Adaptive retry/backoff on the
per-fragment fan-out (Part 2) and batching the tree-walk (Part 3) are deliberately out of scope and
land separately.

## What changed

- `lore-aws/src/aws_error.rs` (new): `is_retryable_sdk_error()` and `is_throttle_code()`, backed by
  an explicit `RETRYABLE_STATUS_CODES = [429, 500, 502, 503, 504]` and a throttle-code list, with
  Smithy shape-id namespace stripping so throttle-code matching isn't fooled by a qualified id.
- `lore-aws/src/store/immutable_store.rs`: new `metadata_load_error()` — a retryable SDK error now
  maps to `SlowDown`, everything else to an internal error. **No SDK error path yields
  `AddressNotFound` any more.** Genuine absence (DynamoDB `Ok` with no item) and deserialize
  failure still map to `AddressNotFound`, unchanged.
- `do_query`: was flattening every `load_metadata` failure into an internal error; now passes
  `SlowDown` through. This is scope beyond the CR's literal text — `query()` is the exact call the
  push tree-walk makes per fragment, so without this the fix never reaches the boundary
  `inv-ap-large-push-dynamo-fanout-timeout.md` traced. `lore-reviewer` independently confirmed it
  correct and correctly scoped.
- `docs/testing-guide.md`: recorded the throttle-classification test knowledge.

## Why now

Traced by `../lorehub/docs/investigations/inv-ap-large-push-dynamo-fanout-timeout.md`; sequenced as
**blocking step 0** by `../lorehub/docs/adr-00022-caching-strategy-and-sequencing.md`. Spec:
`../lorehub/docs/lore-change-requests/cr-021-throttle-honesty-and-fragment-fanout-backoff.md` (Part
1 only — Parts 2/3 not started).

## Tests and gates

`lore-test-specialist` owned the tests. On `tideshift/main`: `cargo test -p lore-aws` — 107
passed / 0 failed / 2 ignored (pre-existing). `cargo +nightly fmt --all` clean.
`cargo clippy -p lore-aws --all-targets -- -D warnings --no-deps` clean (scoped to `-p lore-aws`;
did not hit the known pre-existing workspace `lore-client` lint). Detailed fixture notes in
`docs/testing-guide.md`.

## Reviewer findings (`lore-reviewer`)

Applied: permanent 5xx (501/505) had been mis-classified as retryable — replaced a loose
`is_server_error()` with the explicit AWS-SDK-matching status set; added an idempotency caveat to
the classifier docs; added the SPDX attribution line to `immutable_store.rs`; stripped the Smithy
shape-id namespace before throttle-code matching.

Declined with grounds: gating `ResponseError` on non-2xx status — a body truncated mid-transfer
arrives with a *successful* status and is still transient; the SDK's own
`TransientErrorClassifier` treats response errors as transient regardless of status.

Corrected: reviewer flagged a missing store-level timeout→`SlowDown` test; one already existed and
is green.

## Notes / surprises

- **The sibling sweep came back empty**, independently confirmed by the reviewer:
  `get_s3_object_contents` gates absence on `NoSuchKey`, `mutable_store`'s load gates it on
  `Ok`-with-no-item, `lock_store` never emits `AddressNotFound`. `load_metadata` was the lone site
  turning an SDK error into absence — one bug, not a class.
- **The merge into `tideshift/main` conflicted, with no upstream fetch involved.** Structural to
  the per-CR-branch model: the CR branch is based on upstream `main`, while `tideshift/main`
  carries 56 of our commits, several already touching this file (~1000 lines of drift). Our fork's
  `load_metadata` takes `(repository: Context, hash: Hash)`; upstream's takes `(hash)`. Six test
  call sites needed porting to match. Expect this on every CR branch — it's the cost of keeping
  upstream PRs clean.
- `test_load_metadata_sdk_service_error_returns_address_not_found` is an **upstream** test that
  pinned the buggy mapping (it injects `ResourceNotFoundException` — a missing *table* — and
  asserted `AddressNotFound`). Deliberately rewritten as
  `test_load_metadata_non_throttle_service_error_is_internal`. Call this reversal out explicitly in
  the eventual `EpicGames/lore` PR description.

## Follow-ups

CR-021 Parts 2 (adaptive retry/backoff on the per-fragment fan-out) and 3 (batching the tree-walk)
remain open, tracked in the CR spec.
