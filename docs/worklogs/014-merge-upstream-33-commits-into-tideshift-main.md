# Merge upstream (33 commits) into `tideshift/main`

**Date:** 2026-07-29
**Status:** Done, merged locally into `tideshift/main`; not pushed. Local `main` fast-forwarded to
`upstream/main`.
**Classification:** [SERVER] for the reconciled conflict (`lore-server`); the merge as a whole
touches both sides of the fork but nothing in `lore-client`'s CLI surface.

## Summary

Merge commit `9fb6883` brings 33 Epic commits (`370536a..c920a7f`: presign/JWT auth hardening, store
self-heal, connect timeouts, request delegation) into `tideshift/main` on top of our tip `84e3133`.
Workspace version stays `0.8.6-nightly`. Routine upstream sync, done to check whether upstream had
diverged in ways that would collide with our ~30 CRs — it mostly hadn't.

## What changed

- `git merge upstream/main` at `9fb6883`, parents `84e3133` (our tip) and `c920a7f` (upstream tip).
- Local `main` also fast-forwarded to `c920a7f`.
- One content conflict, in `lore-server/src/grpc/repository/v1/service.rs`: our CR-016
  `use super::repository_storage_stats;` and upstream's
  `use crate::grpc::forwarded_requests::ForwardedRequests;` landed on the same line of the same
  `use` block. Kept both.
- Three call-site updates in `lore-server/src/grpc/revision/v1/branch_list.rs`: upstream rewrote
  this file (+618/-308) to add remote BranchList delegation, giving `handler()` a fourth parameter
  `forwarded_requests: &Option<Arc<dyn ForwardedRequests>>`. Our three CR-006 protected-branch tests
  now pass `&None` (the local, non-forwarded path they actually assert). Post-review, those three
  tests were relocated inside upstream's new `mod direct_handling` and annotated
  `/* no forwarded requests */`, matching upstream's own 8 local-path call sites and shrinking
  next-merge conflict surface.
- Everything else auto-merged, including files both sides rewrote heavily
  (`lore-revision/src/state.rs`, `lore-revision/src/auth/login.rs`,
  `lore-transport/src/{connection,grpc/mod,auth/exchange}.rs`).

## Why now

Routine upstream sync. The question was whether upstream had diverged in ways that would collide
with our fork's ~30 CRs; the answer is one line-adjacency conflict and three call-site updates —
everything else auto-merged clean.

## Verification

- `cargo check --workspace --all-targets` clean.
- `cargo +nightly fmt --all --check` clean.
- `cargo clippy -p lore-server --all-targets -- -D warnings --no-deps` clean.
- `cargo test -p lore-server`: 948 passed / 0 failed.
- `cargo test -p lore-revision -p lore-transport -p lore-proto -p lore-credential`: all passed / 0
  failed.
- Reviewer additionally ran `lore-storage` + others: 169 + 105 passed / 0 failed.
- Reviewer mechanically verified merge fidelity: across all 127 fork-patched files, our +/- lines
  are byte-identical between `370536a..84e3133` and `c920a7f..9fb6883` except the three `&None`
  call sites above. No silent loss, no semantic inversion, no `unwrap`/`expect` introduced.

## Reviewer findings (`lore-reviewer`)

- **Applied:** the `mod direct_handling` relocation + `/* no forwarded requests */` comment on the
  three CR-006 test call sites.
- **Deferred, flagged as the important one:** upstream's new forwarded-request services
  (`lore-server/src/grpc/forwarded_revision/v1/service.rs:70` and the forwarded repository service)
  expose `branch_create`/`branch_delete`/`repository_create` with **no `require_permission` call**,
  unlike the public `revision/v1/service.rs` equivalents. `forwarded_requests.rs` moves the caller's
  authorization into an `on-behalf-of-authorization` header that nothing ever authorizes on, and
  `grpc/mod.rs:337` fail-opens when no token is in extensions. This is upstream's code, inert today
  (all `RpcFlags` default false; the internal server has no JWT verifier), but it means our
  CR-010/CR-011 "every write is gated" invariant now holds on the **public** service only. Action
  recorded: keep forwarding disabled, keep the internal port off any public interface, and gate this
  before ever enabling it.
- **Deferred:** unreachable-server behavior changed upstream to `Disconnected` under a hard 5s
  connect budget (was `Internal`); `lorehub-desktop/crates/lore-engine/src/error.rs`'s mapping should
  be re-checked. Desktop-side follow-up, not a lore one.
- **Deferred:** `lore-integration-tests/src/revision_tree_test.rs` (+979 from upstream) exercises the
  CR-008/CR-021 path and has not been built; a `--no-run` build was queued but not run.

## Notes / surprises

`cargo test` at default `-j` in this workspace produces bogus `E0786 invalid metadata files` errors
and rustc ICEs — a parallel-build race, not a code fault: the same targets build and pass
one-at-a-time, and the failure reproduced even in a cold, fully isolated `CARGO_TARGET_DIR`. `-j 4`
runs green. Two wrong diagnoses were burned before landing on this (a full C: drive, then
target-dir contention with a concurrent session); the second wrong turn cost a `cargo clean -p` of
five packages that discarded 57 GB of shared build artifacts. Worth remembering before re-diagnosing
this from scratch next time it shows up.

## Follow-ups created

- Gate the forwarded-request services' missing authorization before `RpcFlags` ever enables them
  (tracked verbally above, not yet filed as a CR).
- Re-check `lorehub-desktop/crates/lore-engine/src/error.rs`'s unreachable-server mapping against the
  new `Disconnected` classification (desktop-side).
- Build `lore-integration-tests/src/revision_tree_test.rs` with `--no-run` to confirm it still
  compiles against the merged tree.
