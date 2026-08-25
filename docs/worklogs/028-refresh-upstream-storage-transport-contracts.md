# Refresh upstream storage and transport contracts

**Date:** 2026-08-24
**Status:** Done and verified locally; nothing was pushed.
**Classification:** Mixed [SERVER]/[CLIENT]; the integrated architecture remains valid.

## Summary

Refreshed the fork to upstream Lore `52b8b774`, replayed the existing Tideshift history, and
reconciled upstream's storage, authentication, revision, and transport changes with Lorehub's
shared-cell server model. The integration resolved 21 true conflicts across 54 affected paths,
then completed three reviewer-driven repair rounds for Postgres CAS/copy semantics, credential
cache safety, and concurrent mutable-store outcomes.

## What changed

- Baselines: pre-refresh fork `020e6bde`; fetched upstream and local `main` `52b8b774`; linear
  replay `64a9892`; semantic integration `0bc4b7e`; final reviewed tip `1a7488e`.
- Retired the dynamic per-repository AWS bucket resolver and cross-bucket copy scope. Lorehub keeps
  one fixed shared bucket per regional cell.
- Accepted upstream's unified `ImmutableStore` batch query, `StoreGetData`, `StoreMatchResult`,
  context-carrying replica, and copy contracts, then ported Postgres isolation, deduplication,
  lifecycle, metering, and repository-stat behavior onto them.
- Kept upstream branch-latest CAS and its observed `local_latest` through fork sync while preserving
  exact-selection rollback to the original anchor.
- Combined upstream's actual bound QUIC address and internal ephemeral certificate with the fork's
  endpoint registry and graceful drain.
- Combined upstream HTTP settings with the fork's Postgres maintenance configuration and tests.
- Accepted random AES-GCM nonces while retaining atomic refresh-pair persistence and lease behavior;
  the obsolete nonce counter was removed.
- Used a supplied access token when present, otherwise refreshed the stored auth token, while
  retaining `NotAuthenticated` classification.
- Accepted boxed AWS SDK errors while preserving retry and missing-versus-transient classification.
- Classified the new QUIC `GetResolved` path as read and `PutResolved` as write in both legacy and
  v4 permission gates.
- Preserved the Lorehub hook, Postgres configuration/maintenance, repository-stats RPC, and
  thin-client tracking while accepting upstream handler and protobuf changes.
- The finite conflict inventory and active-active impact analysis live in
  `../../../lorehub/docs/investigations/inv-ds-lore-upstream-refresh-active-active-impact.md` at
  Lorehub commit `609b231`.

## Why now

Gate -1 required a current upstream foundation before active-active work could rely on Lore's real
storage and transport contracts. Refreshing first avoided designing against the older fork while
making each retained Lorehub delta explicit.

## Reviewer findings

- Applied in `9ca4e75`: repaired missing/nonzero Postgres CAS behavior, bounded wildcard immutable
  copy to the source partition, and removed the token-encryption cache panic path.
- Applied in `5e9deaa`: covered an existing zero-valued CAS row without weakening missing-key
  behavior, and extended shared conformance coverage.
- Applied in `1a7488e`: serialized mutable store and CAS outcomes with one per-key transactional
  advisory lock so observation, conditional write, and result share a linearization point.
- Independent final `lore-reviewer` verdict: clear across correctness, idiom, coverage, and retained
  architecture; no deferred code finding.

## Verification

- `cargo +nightly fmt --all -- --check` passed.
- `cargo test -p lore-aws -p lore-credential -p lore-postgres -p lore-proto -p lore-revision
  -p lore-server -p lore-storage -p lore-transport -j 4` passed: AWS 180, credential 40, revision
  library 326 plus state 44, server library 1,102 plus 26 doctests, storage 276, and transport 91.
- `cargo test --workspace -j 4 -- --format terse` passed with zero failures; integration tests were
  184 passed / 1 ignored, with 36 live Postgres tests ignored.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings` passed. Affected-package
  all-target/no-deps Clippy reruns also passed after each repair.
- Post-Clippy checks passed: `cargo test -p lore-revision -j 4` and
  `cargo test -p lore-integration-tests -j 4 -- --format terse` (184 passed / 0 failed / 1 ignored).
- Repair checks passed: `cargo test -p lore-credential -p lore-postgres -j 4` (40 and 6 unit),
  `cargo test -p lore-storage -p lore-postgres -j 4` (276 and 6 unit), and
  `cargo test -p lore-postgres -j 4` (6 unit, 38 live ignored).
- `git diff --check`, cached diff checking, and the strict conflict-marker scan passed.
- The first post-snapshot workspace run returned truncated nonzero output; the immediate terse
  diagnostic rerun above is the recorded full-workspace gate.

## Remaining boundary

No disposable live Postgres URL was available, so this close-out did not execute the 38 ignored
live-backend cases. The committed integration and repair commits are local only; no push occurred.
