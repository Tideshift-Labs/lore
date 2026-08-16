# Preserve topology during parallel multi-path stage

**Date:** 2026-08-16
**Status:** Done; upstream-oriented commit `52732dd`, merged into `tideshift/main` as `50ac981`.
**Classification:** [CLIENT] (`lore-revision` ships in the CLI and links into
`lorehub-desktop`).

## Summary

Parallel multi-path staging could report success for every selected nested path while omitting
some paths from the serialized staged state and eventual commit. A walker copied a directory node
before awaited work, then restored the stale whole node after a sibling walker had updated its
child topology. Stage now writes only the current-node fields owned by the operation, preserving
concurrent child and sibling links.

## What changed

- `lore-revision/src/stage.rs` replaces case-rename whole-node assignment with name-only updates
  against the current node.
- Content and type transitions update only the current node's File flag, child pointer, mode, and
  size. Force, dirty-add restaging, and merge flags no longer authorize a stale whole-node write.
- `lore-revision/tests/stage_topology.rs` adds a real 16-worker Tokio regression fixture. Its eight
  lifecycle rows reload the staged anchor and verify the exact committed tree: committed-directory
  force false/true, staged-add-directory force true, file/directory transitions, undelete force
  false/true, and case-only rename.
- The same test target pins sequential `merge_resolve_theirs` flags and the deferred staged content
  address through commit.

## Why now

Exact-selection commit v1 needs Lore staging to retain every selected path before a transaction can
make the larger operation atomic. The failure reproduced on clean upstream `main` at
`a43f648411179f0de690f7f63c2664916f8be466`, so the correction is being kept suitable for upstream
review. See [CR-023](../../../lorehub/docs/lore-change-requests/cr-023-parallel-stage-topology-correctness.md)
and [WP1](../../../lorehub-desktop/docs/work-packages/wp-exact-selection-lore-stage-topology.md).

## What this unblocks

WP3 can build the exact-selection transaction primitive on a stage operation whose admitted path
topology survives a real multi-worker runtime. WP2 metadata error propagation remains independent.

## Reviewer findings

The applied review findings narrowed case renames to name fields and content/type changes to the
File flag, child pointer, mode, and size on the current node. Regression coverage now pins those
structural transitions. Final `lore-reviewer` pass found no blockers.

## Verification

- New topology target: 2 passed / 0 failed, covering eight lifecycle rows plus sequential merge.
- Existing focused stage suite: 7 passed / 0 failed.
- Existing focused commit suite: 3 passed / 0 failed.
- Scoped `lore-revision` Clippy with warnings denied: clean.
- `cargo +nightly fmt --all -- --check`: clean.
- Workspace Clippy did not complete cleanly: after one timeout, it was blocked only by the
  pre-existing unrelated `lore-client/src/cli/commands/branch.rs:1369` `collapsible_match` warning.

## Boundaries

Coverage establishes ordinary file staging and sequential merge resolution. Links, layers, and
concurrent merge topology remain unsupported and unclaimed.
