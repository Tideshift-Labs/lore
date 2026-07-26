# Add RepositoryStorageStats, a per-repo stored-bytes RPC (CR-016)

**Date:** 2026-07-26
**Status:** Done (fork-side, merged locally into `tideshift/main`; not pushed or submitted upstream)
**Classification:** [SERVER]. The `lore-storage` trait addition ships in a CLI crate but is
additive, has a default `NotSupported` body, and has no call site reachable from the `lore` CLI —
loreserver's handler is its only non-test caller.

## Summary

Lore persists every fragment's exact stored size (`size_payload`, `size_content`) and the
fragment-to-repo association, but exposed neither: no RPC reported what a repository actually
occupies, and S3 listing can't recover it (object keys are bare content hashes in one shared bucket,
no repo prefix). Lorehub needs the number to meter storage COGS (WP-070 Track B). Added a read-only
`RepositoryStorageStats` to `lore.repository.v1.RepositoryService`, returning the distinct fragment
count and payload/content byte sums for one repository.

## What changed

- `lore-proto`: additive `RepositoryStorageStats` request/response on `RepositoryService`
  (`.proto` + regenerated `lore.repository.v1.rs`); a comment on the RPC names the hunk to
  reconcile if upstream ever adds its own storage-accounting call.
- `lore-storage`: new `StoreRepositoryStats` type; new **default** `ImmutableStore::repository_stats`
  trait method returning `NotSupported`.
- `lore-postgres`: overrides `repository_stats` with one query — DISTINCT over the repository's
  hashes joined to the per-hash size index. New `lore_fragments_repo_hash (repository, hash)` index,
  added to *both* schema authorities: the inline `SCHEMA` const (`ensure_schema`'s runtime source)
  and `migrations/0001_init.sql` (the out-of-band provisioning artifact) — a cell provisioned by only
  one silently lacks the index.
- `lore-server`: new handler file `grpc/repository/v1/repository_storage_stats.rs`, wired into
  `service.rs`; authorizes via `check_repository_query_authorization` (CR-011's ReBAC callback), not
  the JWT path — see below.
- `lore-server/src/store/{grpc_replica,replicated_store}.rs`: no override; both inherit the trait
  default and are documented as such.
- Tests: `lore-postgres/tests/immutable_store.rs` (+289 lines), `lore-proto/tests/v1_repository.rs`.
- `docs/testing-guide.md` (+121 lines, test-specialist-owned).
- Second commit `aa0174a`: unrelated one-line drift found while running the gate — the
  `v1_thin_client_field_shapes` test in `lore-proto` predated CR-008's `size_bytes`/
  `total_size_bytes` fields and no longer compiled; fixed, test-only.

Landed directly on `tideshift/main`, no per-CR branch — deliberate departure from the usual pattern:
the backend half targets `lore-postgres`, a fork-only CR-007 crate absent from upstream `main`, so a
branch cut from upstream couldn't carry it, and the CR isn't upstreamable as a unit. No upstream PR
opened or prepared; both commits are DCO-signed with the AI-authorship line regardless, to keep that
option open.

## Why now

CR-016, spec'd at `../lorehub/docs/lore-change-requests/cr-016-repository-storage-stats.md`, driving
WP-070 Track B (Lorehub storage-COGS metering).

## Decisions and findings worth recording

- **Authorization was the real risk.** `RepositoryService` (v0 and v1) rides the authn-only
  `JWTAuthnInterceptor` (`server.rs:675`, `TODO(UCS-13506)`), not a repo-scoped one. The JWT
  `verify_authorization` path would have compiled, read plausibly, and enforced nothing — the handler
  instead re-checks the body-supplied repository id through CR-011's ReBAC callback before touching
  the store.
- **Backend coverage is deliberately partial.** DynamoDB's fragments table is partition-keyed by
  hash with no repository GSI; answering there would mean a hidden full-table Scan billed to a
  caller asking about one repository — rejected by the CR. Wrapper stores (composite / replicated /
  remote) inherit the default too: `ReplicatedStore` forwards over the store *protocol* (QUIC), which
  has no message for this, so extending it was ruled out of scope and documented on the trait.
  Production is unaffected — `mode = "postgres"` hands services the raw store directly.
- **Semantics, not a bug:** under global dedup, bytes shared across repositories count in full for
  every referencing repository, so sums are referenced footprints, and cross-repo totals exceed
  physically-stored bytes. That's the intended metering figure.
- **Deployment constraint:** `ensure_schema` runs its DDL inside a transaction, so the new index
  can't be built `CONCURRENTLY` there. On an existing cell, build it out-of-band before rolling the
  binary and check `pg_index.indisvalid` afterward — a failed `CONCURRENTLY` build leaves an INVALID
  index that `IF NOT EXISTS` skips forever.
- Postgres `SUM(bigint)` returns `numeric`, no `FromSql` for our types — hence the `::bigint` casts.
- The highest-value verification here was executable, not textual: the pg suite skips without live
  infra, so green up to that point was stub-level only. Stood up real Postgres + MinIO in Docker; 15/15
  passed for real, and `EXPLAIN (ANALYZE)` over 50k fragments / 500 repos showed a bitmap index scan
  on the new index plus a PK scan for the join — no sequential scan, 1.04ms.

## Reviewer findings (`lore-reviewer`)

Confirmed [SERVER], including the `lore-storage` trait addition, via the CLI-exposure checklist (nil
reachability from the `lore` CLI). Applied: SPDX header corrected to the `drain.rs` fork precedent,
`row.get` → `try_get` (the only non-test panic path), the wrapper-store forwarding gap documented on
the trait, deliberate absence of a `LORE_CONTEXT` scope noted. Deferred: per-call cost is O(fragments
in repo) with no cap (acceptable at metering cadence); the permanent fork delta across three
CLI-shipped `lore-storage` files.

## Tests and gates

Scoped `-p lore-server -p lore-postgres -p lore-storage -p lore-proto`, re-verified after the review
fixes: `cargo test` — 895 + 158 + 26 + 15 (+ smaller suites), 0 failed. `cargo clippy --all-targets --
-D warnings --no-deps` clean. `cargo +nightly fmt --check` clean. Workspace-wide clippy stays scoped;
it's red on a pre-existing `lore-client` lint that isn't ours.

## Follow-ups

- Lorehub-side follow-up (`proto:refresh`, the `@lorehub/lore-client` surface, WP-070's `repo.meter`
  job step 5) is a separate session in `lorehub`.
- Wrapper-store forwarding (replicated/composite) remains `NotSupported`; revisit only if a cell
  needs metering through a wrapped store.
- Two gotchas already captured in `docs/testing-guide.md`, not repeated here: `protoc` isn't on PATH
  on this rig (used the one bundled with the `grpc.tools` nuget package); chaining
  `cargo clippy` with `cargo test` in one invocation can produce a bogus
  `crate lore_revision required to be available in rlib format` error (clippy leaves check-only
  artifacts where the test link step wants rlibs) — run them separately.
