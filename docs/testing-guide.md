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
  rebuild the whole workspace for a one-crate change; workspace-wide test builds add tens of GB to
  `target/` — see `lore/CLAUDE.md` "Local-test gotchas").
- **Integration** — `lore-integration-tests` + per-crate `tests/`; heavier, may need fixtures/backends.
- Filter to a module path with `cargo test -p <crate> --lib <module>::` — note cargo only accepts
  **one** filter argument; run separate invocations per module rather than a space-joined list.
- `cargo clippy -p <crate> --tests --no-deps -- -D warnings` scoped the same way is fast (~30s
  incremental) once the lib itself has compiled once; use it as a pre-report gate on test code.

## Gates (match `lore-reviewer`'s bar)

- `cargo test`
- `cargo +nightly fmt --all`
- `cargo clippy --all-targets -- -D warnings --no-deps` (zero warnings)
- Engine code standards: **no `unwrap`/`expect` in non-test code**, layered `thiserror`→`LoreError`,
  `lore_spawn!`-only task spawning, SPDX headers, DCO `Signed-off-by` on anything intended to upstream.

## Our deltas (keep current — which crates we've touched + how they're tested)

Per the `lore-fork-patches-inventory`: our `tideshift/main` commits are mostly SERVER-side
(loreserver / lore-aws / v1 gRPC), with one client-path change (native TLS roots in `lore-transport`,
not the CLI itself). As you test a delta, record here **which crate it's in and how it's covered**, so
the next run starts from the map instead of rediscovering it.

- **CR-004 (write-permission enforcement)** — `lore-server/src/grpc/revision/v1/service.rs`. Gate is
  `require_permission(...)` inline in `branch_create`/`branch_delete`/`branch_push` (NOT
  `branch_metadata_set`, which instead threads `enforce_write_permission` down into its own handler).
  Tests: `grpc::revision::v1::service::tests` (`read_only_token_push_is_denied`,
  `all_write_rpcs_reject_read_only_token`, etc.) — `cargo test -p lore-server --lib -- grpc::revision::v1::service`.
- **CR-006 (protected-flag surfacing)** — `lore-server/src/grpc/revision/v1/branch_get.rs`, the
  `get_by_id_*_protected_*` tests near the bottom of the file, calling `handler(...)` directly (not
  `branch_get_implementation`) so they also exercise the forwarding seam.
  `cargo test -p lore-server --lib -- grpc::revision::v1::branch_get`.
- **CR-007 (Postgres stores)** — `lore-postgres/`. Only 2 real unit tests in `src/` (`pool::tests::*`);
  the meat is in `tests/{lock_store,mutable_store,immutable_store,concurrency}.rs`, gated on
  `LORE_TEST_PG_URL` — each test does `let Some(url) = pg_url() else { eprintln!(...); return; }`
  when unset, so `cargo test -p lore-postgres --tests` reports **green with zero real assertions run**
  when no Postgres is reachable. Don't read a bare pass as coverage; check for the "skipping" eprintln
  or set `LORE_TEST_PG_URL` (see `integration-harness` skill for a local Postgres, e.g.
  `postgres-cell-pg` compose profile) to actually exercise CR-007.
- **lore-aws (DynamoBucketResolver / per-tenant isolation)** — `lore-aws/src/store/`. Unit tests run
  fully offline (mocked SDK clients), `cargo test -p lore-aws --lib`: 86 passed, 2 `#[ignore]`d
  (`test_put_immutable_partial*`, need real S3 multipart) — pre-existing ignores, not ours.
  `store::bucket_resolver::test::*` covers the tenant-routing/fail-closed behavior.
- **CR-005 (lorehub_notify post-commit hook)** — `lore-server/src/hooks/`. Fully unit-tested, no
  external service needed: `cargo test -p lore-server --lib -- hooks` (98 passed).
- **lore-transport native TLS roots (CLIENT, commit 2176c74)** — `lore-transport/src/auth/ucs_auth.rs`
  `connect_client`. No dedicated unit test (the commit was verified end-to-end manually, per its
  message); existing `auth::ucs_auth::tests::*` cover URL/scheme parsing, not the TLS config itself.
  `cargo test -p lore-transport --lib` is cheap (~40s cold) and green; treat as smoke-only for this delta.
- **CR-009 (graceful QUIC drain, [SERVER])** — entirely in `lore-server`: new `src/drain.rs`
  (`DrainConnection` trait, `ConnectionRegistry<C>`, `DrainState`, `run_drain`),
  `ServerSettings.{graceful_drain, drain_timeout_seconds, drain_stall_timeout_seconds}` (all
  `#[serde(default)]`, default-off), `wait_for_shutdown` changed `Duration` → `Option<Duration>`
  (`None` = unbounded), `ServerHealth.drain: Option<Arc<DrainState>>` gating a 503 in
  `/health_check`, and the new unauthenticated `/drain_status` JSON route. Coverage:
  `cargo test -p lore-server --lib drain::` (registry + pending-handshake mechanics, `run_drain`
  timing/stall-guard incl. single-close-per-window), `--lib server::tests::wait_for_shutdown_tests`
  (bounded force-abort unchanged, unbounded mode actually waits), `--lib settings::tests` (new keys
  parse + default), `--lib health_check::` / `--lib drain_status::` (503-on-drain, JSON shape, route
  placement). Real QUIC endpoint behavior (accept-loop refusal in `quic/quinn/quinn_server.rs`)
  intentionally left to manual/e2e — no mock-friendly seam there.
- **CR-010 (`NotificationService.Subscribe` repo-authz cross-check, [SERVER])** —
  `lore-server/src/grpc/notification_service.rs`. The JWT interceptor authorizes the repository in
  request **metadata**; `subscribe` streams the repository in the request **body** — previously no
  cross-check. Fix: when an `AuthorizationToken` extension is present, `verify_authorization(token,
  body_repository)` before `sender.register(...)`; no token (auth-OFF) is unaffected. Tests:
  `grpc::notification_service::tests` — `subscribe_denies_body_repository_not_covered_by_token`,
  `subscribe_denies_token_with_no_granted_resources`,
  `subscribe_accepts_exact_repository_match_and_streams_events`,
  `subscribe_accepts_wildcard_token_for_any_repository`, `subscribe_unaffected_when_auth_is_off`,
  plus 2 zero-repository regression cases (with/without a token) —
  `cargo test -p lore-server --lib -- grpc::notification_service`. The deny path is verified via the
  returned `Status` only, not by also asserting no stream got registered for the denied repository:
  `crate::notification::local::NotificationSender`'s internal `DashMap` is private to that module and
  unreachable from a sibling test module. Asserting that directly would need a `#[cfg(test)]`-gated
  accessor on `NotificationSender` — an implementation change, so flag it rather than add it
  unilaterally from a test-only pass.

---

## Deep findings / gotchas (append as discovered)

> Add an entry whenever something cost a real debugging/churn cycle. Format **symptom → cause → what to
> do**, with a `cargo` command or `file:line`. Terse. If a finding generalizes beyond testing, flag it
> for a close-out learning/skill (or a `lorehub/docs/lore-change-requests/` note).

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
- **Deterministic tokio-timer tests: `#[tokio::test(start_paused = true)]`.** `lore-server`'s `drain`
  module runs on real `tokio::time::interval` ticks (1s drain loop, 250ms wait_idle poll) — too slow
  to assert with real sleeps. Under a paused clock, tokio auto-advances virtual time to the next timer
  once every task is blocked on one — no manual `advance()` needed; wrap awaited futures in
  `tokio::time::timeout(...)`. Pattern throughout `drain::tests`. **Gotcha:** `start_paused` needs the
  tokio `test-util` feature, which the workspace `tokio` dep does NOT enable — add it as a crate-local
  `[dev-dependencies]` override (`tokio = { workspace = true, features = ["test-util"] }`,
  `lore-server/Cargo.toml`). Symptom without it: `error[E0599]: no method named 'start_paused' found
  for struct tokio::runtime::Builder` — a misleading error; it's the macro expansion failing on the
  feature-gated method.
- **White-box state via a same-file `#[cfg(test)] mod tests`.** A test module declared inside the
  defining file is a child module and gets field-privacy access to its parent's private fields — use
  it to simulate otherwise-unconstructible states (e.g. a `ConnectionRegistry<quinn::Connection>` with
  N "active" connections, since a real `quinn::Connection` only comes from a live handshake:
  `registry.count.store(n, Ordering::Relaxed)`). A *sibling* module (e.g. `http::drain_status::tests`)
  cannot reach those fields and must use the public API.
- **`DrainConnection` mock pattern (`drain::tests::MockConn`).** Wraps `Arc<AtomicU64>` frame count +
  `Arc<AtomicU64>` close-call counter so a clone kept by the test observes the same state as the clone
  the registry holds (registries store connections by value). `drain_close()` only counts the call; it
  does NOT deregister — mirroring production, where the connection *handler* drops the
  `ConnectionGuard`. Stall-guard tests therefore hold the guard and assert the counter, not
  `active() == 0`. Note `DrainState` is concretely typed to `QuinnConnectionRegistry`, so mocks only
  inject at the `ConnectionRegistry<C>`/`run_drain` layer; at the `DrainState` layer use the
  private-field poke instead.
- **`lore-server` HTTP handler tests — `axum_test::TestServer` pattern.** Single-route
  `axum::Router::new().route(..., routing::get(handler).with_state(...))` for handler-only tests; go
  through `crate::http::server::create_router(...)` (needs `crate::store::test_store_create()`) when
  testing route **placement** (e.g. `/drain_status` in the unauthenticated merge, not the `/v1` nest).
  Assert JSON bodies via `serde_json::Value` rather than adding `Deserialize` to a prod-`Serialize`-only
  response struct.
- **Constructing gRPC-service unit tests without a live server.** `tonic::Request::new(SomeRequest {
  .. })`, then either `.metadata_mut().insert_bin(REPOSITORY_ID_KEY,
  tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()))` (what the JWT interceptor
  would have derived from request metadata) or `.extensions_mut().insert(AuthorizationToken { .. })`
  (what handlers reading the token straight out of extensions expect, e.g.
  `notification_service.rs::subscribe`) — then call the trait method directly on a
  directly-constructed service (`NotificationService::new(Arc::new(sender))`,
  `LoreLockService::new(...)`); `#[tokio::test]` is enough, no tonic transport needed.
  `RepositoryId = lore_base::types::Partition`, `BranchId = lore_base::types::Context`; both have
  `Distribution<_> for StandardUniform` (`rand::random::<RepositoryId>()` works) and `From`/`Into` to
  `bytes::Bytes` (`lore-base/src/types/mod.rs`), so building proto message bytes is just
  `Bytes::from(repository)`. `AuthorizationToken` derives `Default` — build with `AuthorizationToken {
  resources: Some(vec![ResourcePermission { resource_id: format!("urc-{repository}"), permission:
  vec![] }]), ..Default::default() }` (wildcard = `"urc-*"`), matching `forwarded_requests.rs`'s
  existing test style.
- **`Result::expect_err` won't compile on a streaming RPC response.** `Response<Pin<Box<dyn
  Stream<...> + Send>>>` (e.g. `SubscribeStream`) isn't `Debug`, and `expect_err` requires the `Ok`
  side to impl it — `error[E0277]` pointing at `expect_err`. Use `.err().expect("msg")` instead; only
  the `Err`/`Status` side needs `Debug`.
- **Wrap stream-delivery assertions in `tokio::time::timeout`.** After a successful `subscribe`,
  calling a `NotificationSender` trait method (`branch_created`, ...) and then `.next().await`ing the
  returned stream to assert an event arrives: wrap that await, e.g.
  `tokio::time::timeout(Duration::from_secs(5), stream.next()).await.expect("timed out ...")`. A
  regression that silently drops the event would otherwise hang the test instead of failing fast.
  Default pattern for any stream-delivery assertion, not a one-off — see
  `notification_service.rs::tests::subscribe_accepts_exact_repository_match_and_streams_events`.
