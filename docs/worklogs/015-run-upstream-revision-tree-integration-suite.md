# Run upstream revision-tree integration suite after merge

**Date:** 2026-07-29
**Status:** Done (verification and documentation only; no runtime or test-code change)
**Classification:** Mixed evidence: CR-008 [SERVER], CR-021 Part 2b [CLIENT]-relevant, and
CR-021 Part 2c [CLIENT]. This chunk itself is docs-only.

## Summary

Executed the revision-tree integration suite introduced alongside upstream commit `fe9a1c7` after
the upstream merge. All 14 focused tests passed, and the full default `lore-integration-tests`
suite passed 126 tests with one explicit benchmark ignore. The run confirms the merged public
revision-tree API works against the suite's in-memory storage path without claiming coverage of
server or cloud infrastructure.

## What changed

- Ran `cargo test -p lore-integration-tests revision_tree_test -j 4`: 14 passed, 0 failed, 0
  ignored, 113 filtered.
- Ran `cargo test -p lore-integration-tests -j 4`: 126 passed, 0 failed, with the benchmark
  `put_batch_api_within_overhead_budget_of_direct_write_content` explicitly ignored.
- Verified the suite uses `LoreStorageOpenArgs { in_memory: 1, .. }`. No loreserver, MinIO,
  DynamoDB, or Consul was started or contacted.
- Audited the crate's infrastructure handling: AWS/gRPC suites are compile-time feature-gated,
  Consul cases are explicit `#[ignore]`, and setup returns only handle idempotent
  bucket/table-exists outcomes. No missing infrastructure was reported as a passing test.
- Updated `docs/testing-guide.md` with the commands, counts, scope, infrastructure model, and
  coverage boundaries for future runs.

## Why now

Worklog 014 built the newly merged `lore-integration-tests/src/revision_tree_test.rs` with
`--no-run` but did not execute it. This follow-up runs that evidence against the merged tree and
closes the upstream-sync ITEM 2 verification gap.

## Coverage boundaries

The suite covers revision-tree batch fan-out, event ordering, multi-level and mixed-parent
batches, concurrency, atomic rejection, error cases, entry-field round-trip including
`size = 4096`, and a batch larger than one node block.

The size assertion stops below CR-008's server protobuf, handler, and aggregate-size paths. The
suite also does not inject `SlowDown`, so it does not replace the direct CR-021 Part 2b or Part 2c
regressions.

## Reviewer findings

- Applied: described `fe9a1c7` as the upstream batch-API change that introduced this integration
  suite, not as a test-only commit.
- Applied: stated both the CR-008 server-path boundary and the absence of injected `SlowDown`.
- Deferred: none. No implementation defect or user decision arose from this verification.

## Final verification

- Focused revision-tree integration suite: 14 passed / 0 failed / 0 ignored.
- Full default integration crate: 126 passed / 0 failed / 1 explicit benchmark ignored.
- `cargo +nightly fmt --all`: clean.
- Clippy with `-D warnings --no-deps`: clean; only benign build-script warnings about the missing
  installed Lore binary.
