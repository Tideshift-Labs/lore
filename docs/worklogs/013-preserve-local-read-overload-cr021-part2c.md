# Preserve local-read overload classification (CR-021 Part 2c)

**Date:** 2026-07-29
**Status:** Done (fork-side, merged locally into `tideshift/main`; not pushed or submitted upstream)
**Classification:** Part 2c is [CLIENT] because `lore-storage` ships with the CLI. Its review rider
is [SERVER] in production plus [CLIENT test-only] hardening in the shared crates.

## Summary

`lore_storage::read::load_fragment` now preserves an exhausted local `StorageError::SlowDown`
instead of flattening it into the remote-fallback path. Part 2b's fragmented-root handling is now
reachable, while every other local error retains its previous fallback. The review rider also
stopped permanent S3 payload-read failures from being mislabeled as overloads. No signatures changed.

## What changed

- `lore-storage/src/read.rs`: returns only `StorageError::SlowDown` after `read_raw` exhausts its
  existing retry budget, before attempting the remote read. The public `load_fragment` docs now
  state this overload behavior.
- Storage regressions pin the offline/local `SlowDown` result, genuine local absence followed by
  remote fallback, and fallback after a generic internal error. They require at least two local
  read attempts, proving the retry path ran.
- `lore-revision/tests/state.rs`: retains the full fragmented-root fixture and positive control,
  then flips the Part 2c pin to `Err`/`SlowDown`. A constructor installs the fast retry policy
  before any harness code can win the process-wide policy race.
- `lore-aws/src/store/immutable_store.rs` and the fork-only Postgres counterpart now classify S3
  payload reads specifically: `NoSuchKey` is `AddressNotFound`, retryable SDK failures are
  `SlowDown`, and permanent or non-SDK failures are `Internal`. This corrects the CR's stale “no
  throttle concept” wording for Postgres; genuine Postgres absence remains unchanged.
- Commits: Part 2c `f167ee3` (merge `becb0a6`); rider `4b87772` and `d7f2ee2`
  (merge `2c35896`); Postgres counterpart `0cb1d18`.

## Why now

CR-021 Part 2b taught the fragment walk to propagate `SlowDown`, but `load_fragment` had already
discarded that classification before the walk could see it. In every offline server context, the
remote fallback then replaced the local overload with a `NoRemote`-shaped error, so the fragmented
subtree was still silently dropped. Part 2c closes the gap where the classification was lost.

## Reviewer findings

- P2-1 applied: replaced the broad AWS S3 payload mapping with the read-specific classifier, then
  mirrored it in the fork-only Postgres store.
- P3-2 applied: overload tests now prove at least two `get()` calls.
- P3-3 applied: the revision test binary installs its retry policy before harness setup.
- P3-4 and reviewer nit applied: renamed the fixture to `Internal` and the pin from `swallows` to
  `propagates`.
- The earlier public `load_fragment` documentation finding also remains applied.

## Final verification

- `cargo test -p lore-storage`: 161 passed.
- Full `lore-revision` suite: green, including 42 state tests and the fragmented-root pin.
- `cargo test -p lore-aws`: 112 passed, 2 ignored.
- `lore-postgres`: 6 unit tests passed; live-service tests remain explicitly ignored.
- Nightly formatting and scoped clippy with `-D warnings --no-deps`: clean.
- The initial combined run exhausted the Windows paging file. The same suites passed sequentially
  with `-j 2`; this was host resource pressure, not a test failure.

CR-021 Part 3, batching the fragment tree-walk reads to reduce fan-out, remains separate performance work.
