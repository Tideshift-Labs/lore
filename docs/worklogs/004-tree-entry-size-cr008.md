# 004 — Expose per-entry + revision total byte size on revision reads (CR-008)

**Date:** 2026-07-04
**Status:** Done (fork-side). Branch `cr-008-tree-entry-size` merged into `tideshift/main`.

## Summary

Additive enrichment of the `lore.thin_client.v1` revision read path so Lorehub can compute
repo-composition analytics (byte sizes) without fetching blobs: `TreeNode.size_bytes` (FILE-only,
optional uint64) on tree reads, and `Revision.total_size_bytes` (recursive content-byte sum) on
revision-info reads. **[SERVER]** — low-risk, we control the build; no CLIENT-side (`lore-client`)
change. WP-061 Track A; this is the Lore-fork half only — the lorehub-side surfacing + e2e lands
separately.

## Why now

Lorehub needs repo-composition analytics (total/per-file sizes) and the existing thin-client
revision reads carry no size data, forcing a blob fetch just to get byte counts. Governing spec:
`../lorehub/docs/lore-change-requests/` CR-008 (WP-061 Track A).

## What changed

- `lore-proto/proto/lore/thin_client/v1/model.proto`: `TreeNode.size_bytes` (optional uint64, tag
  4 — unset for DIRECTORY/LINK; present `0` is a genuinely empty file, distinct from
  unset/unknown) and `Revision.total_size_bytes` (optional uint64, tag 11 — recursive sum, read
  from the tree root's `size`).
- Regenerated `lore-proto/src/grpc/lore.thin_client.v1.rs` (standalone protoc 28.3, downloaded —
  rig had none installed; verified only this generated file changed, crate otherwise builds off
  committed generated code).
- `lore-revision/src/state.rs`: `TreePath` gained `pub size: u64`, populated from `node.size` in
  `gather_tree_paths_node`.
- `lore-server/src/grpc/thinclient/v1/revision_tree.rs`: file-gates `size_bytes` onto the
  response.
- `lore-server/src/grpc/thinclient/v1/revision_info.rs`: `total_size_bytes` from
  `state.tree(repo).await?.size`, non-fatal (warn + `None` on tree-read error — doesn't fail the
  whole revision-info response).
- Commits: `810876b` (impl, on `cr-008-tree-entry-size` branch), `fd4f8c7` (merge into
  `tideshift/main`), `5211585` (testing-guide record).

## Tests

5 new, all green: `revision_tree.rs` — `file_size_bytes_reflects_node_content_size` (Some(123) +
a 0-byte file asserting `Some(0)`), `directory_size_bytes_is_unset`, `link_size_bytes_is_unset`
(new fixture `push_branch_with_sized_files`); `revision_info.rs` —
`total_size_bytes_is_present_for_revision_with_files`, `empty_revision_has_zero_total_size_bytes`.
`cargo test -p lore-server` (752 passed) + `-p lore-revision` (150).

**Known coverage boundary:** the `lore-server` handler unit-test fixtures build trees via raw
`node_add` and never drive the commit-time size rollup, so `total_size_bytes` only asserts
`Some(0)`/`Some(_)` at this tier — real per-file sizes and the aggregate get verified end-to-end
at the lorehub integration/e2e tier (Stage 2, tracked separately, in progress).

## Reviewer findings (lore-reviewer)

Confirmed **[SERVER]**, no correctness/safety findings. Applied: a doc-comment nit on
`TreePath::size`. Nothing deferred.

## Gates

`cargo test -p lore-server` (752) + `-p lore-revision` (150) green; `cargo +nightly fmt --all`;
`cargo clippy -p lore-server -D warnings` and `-p lore-revision -D warnings` clean.
Workspace-wide `clippy` intentionally not run (pre-existing upstream `lore-client` lint, not ours
— same posture as worklogs 002/003).

## Follow-ups created

- `docs/testing-guide.md` gained the CR-008 coverage record (commit `5211585`).
- Lorehub-side lore-client surfacing + integration/e2e coverage for `total_size_bytes` and
  per-file `size_bytes` is a separate, in-progress lorehub commit (Stage 2).
- DCO `Signed-off-by` + AI-authorship disclosure are on the impl commit, keeping the upstream
  `EpicGames/lore` PR option open. Confirmed upstream 0.8.5 has no existing size field on these
  messages (no collision).
