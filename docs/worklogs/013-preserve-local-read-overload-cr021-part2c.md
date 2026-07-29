# Preserve local-read overload classification (CR-021 Part 2c)

**Date:** 2026-07-29
**Status:** Done (fork-side, merged locally into `tideshift/main`)
**Classification:** [CLIENT]. Both crates ship with the CLI, so custom client stores can observe
the new error. Stock CLI stores cannot emit it by default; server stores are the production emitters.

## Summary

`lore_storage::read::load_fragment` now preserves an exhausted local `StorageError::SlowDown`
instead of flattening it into the remote-fallback path. Part 2b's fragmented-root handling is now
reachable on the server path, while genuine absence, corruption/decompression failures, and every
other local error retain their previous fallback behavior. No signatures changed.

## What changed

- `lore-storage/src/read.rs`: returns only `StorageError::SlowDown` after `read_raw` exhausts its
  existing retry budget, before attempting the remote read. The public `load_fragment` docs now
  state this overload behavior.
- Storage regressions pin the offline/local `SlowDown` result, genuine local absence followed by
  remote fallback, and fallback after a generic deserialize-shaped local error. Paused Tokio time
  avoids racing the process-wide retry-delay `OnceLock`; `lore-storage/Cargo.toml` enables it.
- `lore-revision/tests/state.rs`: retains the full fragmented-root fixture and positive control,
  then flips the Part 2c characterization pin from the old swallowed `Ok` result to
  `Err`/`SlowDown`.
- The fork testing guide records the resulting coverage and test-harness detail.
- Implementation commit `f167ee3` was merged into `tideshift/main` as `becb0a6`.

## Why now

CR-021 Part 2b taught the fragment walk to propagate `SlowDown`, but `load_fragment` had already
discarded that classification before the walk could see it. In every offline server context, the
remote fallback then replaced the local overload with a `NoRemote`-shaped error, so the fragmented
subtree was still silently dropped. Part 2c closes the gap where the classification was lost.

## Storage-mode clarification

The CR's earlier statement that Postgres mode has “no throttle concept” is stale. This fork
deliberately maps transient database, pool, and S3 failures to `SlowDown`; those overloads are now
preserved honestly by the shared read path. Genuine Postgres not-found still remains
`AddressNotFound`, unchanged.

## Reviewer findings

- Applied: documented the overload exception on the public `load_fragment` API.
- Deferred as nonblocking: add a direct corrupt/decompression fallback regression.
- Deferred as nonblocking: a test naming nit.
- No correctness or safety blocker remained.

## Verification

- `cargo test -p lore-storage`: 169 passed.
- `cargo test -p lore-revision -j 1`: 602 passed, 1 ignored
  (`reset_staged_file_refuses`, pre-existing).
- Focused state suite: 42 passed, including the fragmented-root pin.
- `cargo +nightly fmt --all`: clean.
- `cargo clippy -p lore-storage -p lore-revision --all-targets -- -D warnings --no-deps`: clean.

CR-021 Part 3, batching the fragment tree-walk reads to reduce fan-out, remains separate
performance work.
