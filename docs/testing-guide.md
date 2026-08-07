# Testing guide — Lore fork (our deltas)

**The `lore-test-specialist` agent loads this doc at the start of every run, and appends to it at the
end.** Lore is Epic's mature, FOSS, binary-first VCS engine; we maintain a fork on `tideshift/main`
with a handful of our own commits. This guide is **only about testing OUR deltas** — not Epic's engine
— plus build/test gotchas on our setup. Keep it dense; point to Lore's own docs (`CONTRIBUTING.md`,
per-crate docs) and the `rust-best-practices` / `rust-async-patterns` skills for depth.

> This file lives on `tideshift/main` only. It is **excluded from the per-CR branches** we send
> upstream to EpicGames — keep those PRs scoped to code.

## Classify first — SERVER vs CLIENT

- **[SERVER]** — `lore-server` / `lore-aws` / `lore-proto` etc. Low-risk: we control the build and run
  it. Most of our patches. Test pragmatically against our usage.
- **[CLIENT]** — `lore` / `lore-client` / `lore-revision` / CLI path. Higher-risk, gated on upstream
  merge; test to an EpicGames-reviewer bar and place tests where upstream expects.

## How tests are organized

Large cargo workspace. Match each crate's existing test style — read a neighboring suite + the crate's
docs before adding one.

- **Unit** — co-located `#[cfg(test)]` modules. `cargo test -p <crate>` for the crate in scope (don't
  rebuild the whole workspace for a one-crate change).
- **Integration** — `lore-integration-tests` + per-crate `tests/`; heavier, may need fixtures/backends.

## Gates (match `lore-reviewer`'s bar)

- `cargo test`
- `cargo +nightly fmt --all`
- `cargo clippy --all-targets -- -D warnings --no-deps` (zero warnings)
- Engine code standards: **no `unwrap`/`expect` in non-test code**, layered `thiserror`→`LoreError`,
  `lore_spawn!`-only task spawning, SPDX headers, DCO `Signed-off-by` on anything intended to upstream.

## Our deltas — inventory (keep current)

Per `lore-fork-patches-inventory`: `tideshift/main` commits are mostly SERVER-side
(loreserver / lore-aws / v1 gRPC), with a few client-path deltas. Each entry: what changed, where, how
it's tested. Test everything with `cargo test -p <crate> --lib -- <module path>` unless noted.

- **CR-004 write-permission enforcement [SERVER]** — `lore-server/src/grpc/revision/v1/service.rs`,
  `require_permission(...)` inline in `branch_create`/`branch_delete`/`branch_push` (NOT
  `branch_metadata_set`, which instead threads `enforce_write_permission` down into its own handler).
  Tests: `grpc::revision::v1::service::tests` (`read_only_token_push_is_denied`,
  `all_write_rpcs_reject_read_only_token`, etc.) — `cargo test -p lore-server --lib -- grpc::revision::v1::service`.
- **CR-006 (protected-flag surfacing)** — `lore-server/src/grpc/revision/v1/branch_get.rs`, the
  `get_by_id_*_protected_*` tests near the bottom of the file, calling `handler(...)` directly (not
  `branch_get_implementation`) so they also exercise the forwarding seam.
  `cargo test -p lore-server --lib -- grpc::revision::v1::branch_get`.
- **CR-007 (Postgres stores)** — `lore-postgres/`. Six offline unit tests live in `src/`
  (`pool::tests::*` plus the four S3 classification controls); the live-service tier is in
  `tests/{lock_store,mutable_store,immutable_store,concurrency}.rs`,
  gated on `LORE_TEST_PG_URL`/`LORE_TEST_S3_ENDPOINT`/`LORE_TEST_S3_BUCKET`. **As of 2026-07-26
  (commit `758e340`) these are `#[ignore]`d**, so `cargo test -p lore-postgres --tests` correctly
  reports `18 ignored` with no infra running; run `cargo test -p lore-postgres --tests -- --ignored`
  with the env set to actually exercise CR-007. (Before that commit they were plain `#[test]`s that
  printed a notice and returned when unset, which Rust's harness reported as **passed** — a bare
  green run proved nothing, which is how CR-016's two SQL defects reached staging unexecuted; see
  `lorehub/docs/learnings/prefer-an-executable-check-over-a-source-read-verdict.md`.) A local
  Postgres for this is `integration-harness`'s `postgres-cell-pg` compose profile, or an ad hoc
  `docker run` (see the CR-016 entry below for the exact commands).
  S3 read-error classification is a separate offline unit tier in
  `store::immutable_store::tests::s3_payload_load_error_*`: modeled `NoSuchKey` stays
  `AddressNotFound`, retryable SDK failures become `SlowDown`, and permanent/non-SDK failures become
  `Internal`. Run `cargo test -p lore-postgres --lib s3_payload_load_error`; no Postgres or S3
  endpoint is required.
- **lore-aws (DynamoBucketResolver / per-tenant isolation)** — `lore-aws/src/store/`. Unit tests run
  fully offline (mocked SDK clients), `cargo test -p lore-aws --lib`: 86 passed, 2 `#[ignore]`d
  (`test_put_immutable_partial*`, need real S3 multipart) — pre-existing ignores, not ours.
  `store::bucket_resolver::test::*` covers the tenant-routing/fail-closed behavior.
- **CR-005 (lorehub_notify post-commit hook)** — `lore-server/src/hooks/`. Fully unit-tested, no
  external service needed: `cargo test -p lore-server --lib -- hooks` (98 passed).
- **No-op branch-push side-effect suppression ([SERVER])** —
  `lore-server/src/grpc/handlers/branch_push.rs` and
  `lore-server/src/grpc/revision/v1/branch_push.rs`. Shared `PushResult.advanced` is false when the
  incoming revision already equals the branch head; both handlers gate `branch_pushed` and
  `HookPoint::BranchPush` post-hooks on it. Handler-level regressions first await the advancing
  push's detached notification/hook through `mpsc::unbounded_channel`, then use a bounded 100 ms
  receive to prove the no-op re-push emits neither. They also override `InstrumentProvider::meter`
  with a per-test `SdkMeterProvider` + `InMemoryMetricExporter`, avoiding the process-global meter
  provider, and assert `num_branches_pushed == 1` after both calls. Coverage:
  `cargo test -p lore-server --lib -- grpc::handlers::branch_push::tests` (6 passed) and
  `cargo test -p lore-server --lib -- grpc::revision::v1::branch_push::test` (11 passed).
- **lore-transport native TLS roots (CLIENT, commit 2176c74)** — `lore-transport/src/auth/ucs_auth.rs`
  `connect_client`. No dedicated unit test (the commit was verified end-to-end manually, per its
  message); existing `auth::ucs_auth::tests::*` cover URL/scheme parsing, not the TLS config itself.
  `cargo test -p lore-transport --lib` is cheap (~40s cold) and green; treat as smoke-only for this delta.

---

## Durable gotchas & patterns

### Build & merge hygiene
- **An upstream merge that changes a signature our tests call directly compiles-fails silently until
  you build.** `git diff --stat` on the merge commit won't show it. Always `cargo build -p <crate>
  --tests` before `cargo test` after any merge touching a patched file — a stale call site is a
  compile error, and `cargo test`'s output on a broken build can misleadingly read as "no tests ran"
  instead of surfacing the real rustc diagnostic.
- **Honest skips, not silent passes, for infra-gated tests.** `#[ignore]` a Postgres/S3-gated test
  (run with `-- --ignored`) rather than writing a plain `#[test]` that prints a notice and returns
  when the env var is unset — Rust's harness reports the latter as **passed**, which is how real
  bugs (e.g. two SQL defects, CR-016 lineage) can reach staging with a fully green suite proving
  nothing. See `lorehub/docs/learnings/prefer-an-executable-check-over-a-source-read-verdict.md`.
- **A `cargo build`/`test` error naming a file with zero `git diff` is probably a stale incremental
  cache, not a real error.** Running `cargo clippy` then a separate `cargo build --tests`/`cargo
  test` invocation against the same `target/` can produce a bogus "crate required in rlib format but
  not found" or "cannot determine resolution for macro" error in an untouched file. Fix: `cargo clean
  -p <the-crate-that-actually-errored>` (not a full workspace clean) + rebuild. Check `git status`
  before spending time reading the named file.
- **A CR spec may name a crate that doesn't exist on the branch you're testing from**, if that
  crate was merged into `tideshift/main` after the branch's lineage point (e.g. `lore-postgres`/
  CR-007 on a branch cut from upstream `main`). `cargo check -p <crate>` fails with "package ID
  specification did not match any packages" — not a bug in either delta. Check workspace `members`
  or `git merge-base` against `tideshift/main` before treating a missing `-p <crate>` as a real gate
  failure; flag the lineage gap and re-run after merge.

- **Upstream merge that adds a handler param breaks our tests silently until you build.** Merging
  `upstream/main` (v0.8.5, commit eab1984) added a `forwarded_requests: Option<Arc<dyn
  ForwardedRequests>>` parameter to both `LoreRevisionV1Service::new` and
  `branch_get::handler`. Our CR-004 test helper (`service.rs::tests::service_with`) and three CR-006
  tests (`branch_get.rs::tests::get_by_id_*_protected_*`) called the old arities and failed to
  compile (`E0061 this function takes N arguments but N-1 were supplied`) — `cargo test` never got far
  enough to run anything. `git diff` on the merge commit's stat won't show this; you have to actually
  `cargo build -p <crate> --tests` after a merge that touches a signature our tests call directly.
  Fix (stale-test, ours to fix): pass `None` / `&None` for the new forwarding param in tests that don't
  exercise the forwarding path — `lore-server/src/grpc/revision/v1/service.rs:357`,
  `lore-server/src/grpc/revision/v1/branch_get.rs:743,778,816`.
- **After a merge touching our patched files, `cargo build -p <crate> --tests` before `cargo test`.**
  A stale call-site is a compile error, not a test failure — `cargo test` output on a broken build can
  look like "no tests ran" rather than pointing you at the real cause; build first to get the real
  rustc diagnostic.
