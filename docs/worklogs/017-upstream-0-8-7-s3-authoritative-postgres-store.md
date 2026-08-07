# Merge upstream 0.8.7 and make S3 fragment metadata authoritative

**Date:** 2026-08-07
**Status:** Done; deployed and live-verified on staging
**Classification:** Upstream merge is mixed [SERVER]/[CLIENT]; the Postgres/Spaces redesign is
[SERVER].

## Summary

Merged upstream Lore 0.8.7 into the long-running fork, preserving Lorehub's authorization,
notification, graceful-drain, retry, Postgres, and thin-client deltas. The deployed Postgres/Spaces
immutable store now follows upstream's self-describing-object architecture: S3 object metadata is
the fragment-representation authority, while Postgres retains repository associations, durable
lifecycle state, and an exact rebuildable metering projection.

The unused `lore-aws` dynamic bucket-routing extension was retired rather than adapted. Lorehub's
actual topology remains one config-fixed shared bucket per regional cell, so global hash dedup and
global object state are coherent.

## What changed

- Merge commit `8f8d358` integrates upstream `a43f648` on branch
  `codex/upstream-0.8.7-integration`.
- `lore-postgres` stores associations in `lore_fragments`, lifecycle in
  `lore_fragment_state`, and exact non-authoritative size data in `lore_fragment_metering`.
- Publish writes `lore-fragment` metadata on the S3 object. Metadata reads use HEAD; combined
  metadata/body reads use one GET.
- A per-hash advisory transaction lock serializes publication and lifecycle transitions. Same
  logical content may reuse a first-writer physical representation; conflicting logical sizes fail.
- Missing objects clear stale lifecycle/projection state without destroying repository
  associations. Stats repair missing projections and fail closed on incomplete data.
- Obliteration uses resumable `Stored -> Obliterating -> PayloadDeleting -> Obliterated` phases,
  releases Postgres before S3/recursive work, and exhaustively removes versioned payloads.
- `loreserver --rebuild-postgres-metering` transactionally rebuilds the projection from S3 and
  prints the rebuilt row count before exiting without starting endpoints.

## Why now

Upstream's rewritten AWS store moved fragment metadata onto objects and introduced global lifecycle
state. Keeping the fork's per-repository bucket resolver would have made equal hashes point at
different storage domains while sharing one state row, allowing false durability, destructive
missing-object repair, and incorrect obliteration. The deployed Postgres topology never used that
resolver, and staging data was explicitly disposable, so adopting the coherent upstream model was
safer than preserving an unused capability.

## Reviewer findings

- Applied: shared exact S3 error classification; permanent failures never masquerade as retryable
  throttles or trigger missing-object repair.
- Applied: no Postgres connection is held across S3 or recursive work; pool-size-one traversal and
  both deletion retry phases are covered.
- Applied: version cleanup drains more than one page and uses an isolated temporary bucket in tests.
- Applied: rebuild is transactional and rolls back if a later object has malformed metadata.
- Deployment precondition: old `lore_fragment_state` constraints do not change through
  `CREATE TABLE IF NOT EXISTS`; an existing database needs a migration or a clean reset.
- Deferred: a synthetic 12-level fragmented chain can exhaust the Windows test-thread stack. The
  green regression proves three levels with a pool of one; consider an iterative walker or depth
  bound separately.

## Verification

- Upstream merge suites: AWS 132, storage 215, transport 71, revision 182, server 960 plus 26
  doctests, focused spawn 75, and revised-tree 20; workspace check, fmt, and clippy passed.
- Live disposable Postgres 16 + MinIO: 32/32 tests passed, including 1,001 S3 versions, races,
  collisions, repair, retry, copy, and obliteration.
- Staging `loreserver:554e937`: fresh schema, health/drain 200, zero restarts. A real authenticated
  push produced 11 objects with S3 metadata and 11 association/state/metering rows; a non-empty
  rebuild returned 11 and reproduced 11 rows.

