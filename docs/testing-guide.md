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

## Our deltas — inventory (keep current)

Per `lore-fork-patches-inventory`: `tideshift/main` commits are mostly SERVER-side
(loreserver / lore-aws / v1 gRPC), with a few client-path deltas. Each entry: what changed, where, how
it's tested. Test everything with `cargo test -p <crate> --lib -- <module path>` unless noted.

- **CR-004 write-permission enforcement [SERVER]** — `lore-server/src/grpc/revision/v1/service.rs`,
  `require_permission(...)` inline in `branch_create`/`branch_delete`/`branch_push` (NOT
  `branch_metadata_set`, which threads `enforce_write_permission` into its own handler). Tests:
  `grpc::revision::v1::service::tests`.
- **CR-006 protected-flag surfacing [SERVER]** — `lore-server/src/grpc/revision/v1/branch_get.rs`.
  Tests call `handler(...)` directly (not `branch_get_implementation`) to also exercise the forwarding
  seam. `grpc::revision::v1::branch_get`.
- **CR-007 Postgres stores [SERVER]** — `lore-postgres/`. Offline unit tests in `src/` (`pool::tests::*`
  + 4 S3-classification controls, no infra); live-service tier in
  `tests/{lock_store,mutable_store,immutable_store,concurrency}.rs`, gated on `LORE_TEST_PG_URL` /
  `LORE_TEST_S3_ENDPOINT` / `LORE_TEST_S3_BUCKET` and marked `#[ignore]` (run with `-- --ignored`
  against real infra; without env set they correctly report "18 ignored", never a false "passed" — see
  the honest-skip gotcha below). Local Postgres: `integration-harness`'s `postgres-cell-pg` compose
  profile, or ad hoc `docker run` (commands in the CR-016 entry). S3 read-error classification is a
  separate offline tier: `--lib s3_payload_load_error`.
- **lore-aws DynamoBucketResolver / per-tenant isolation [SERVER]** — `lore-aws/src/store/`. Fully
  offline (mocked SDK clients), `cargo test -p lore-aws --lib`; `store::bucket_resolver::test::*`
  covers tenant-routing/fail-closed. 2 pre-existing `#[ignore]`s (need real S3 multipart), not ours.
- **CR-005 `lorehub_notify` post-commit hook [SERVER]** — `lore-server/src/hooks/`. Fully unit-tested,
  no external service: `--lib -- hooks`.
- **No-op branch-push side-effect suppression [SERVER]** —
  `lore-server/src/grpc/handlers/branch_push.rs` + `.../v1/branch_push.rs`. `PushResult.advanced` gates
  `branch_pushed`/`HookPoint::BranchPush` post-hooks on the incoming revision already equalling the
  branch head. Tests await the advancing push's hook/notification, then bounded-receive (100ms) to
  prove the no-op re-push emits neither; use a per-test `SdkMeterProvider` +
  `InMemoryMetricExporter`, not the process-global meter. `grpc::handlers::branch_push::tests` +
  `grpc::revision::v1::branch_push::test`.
- **lore-transport native TLS roots [CLIENT], commit 2176c74** — `lore-transport/src/auth/ucs_auth.rs`
  `connect_client`. No dedicated unit test (verified manually end-to-end); `cargo test -p
  lore-transport --lib` is smoke-only for this delta.
- **CR-009 graceful QUIC drain [SERVER]** — new `lore-server/src/drain.rs` (`DrainConnection`,
  `ConnectionRegistry<C>`, `DrainState`, `run_drain`), new `ServerSettings.{graceful_drain,
  drain_timeout_seconds, drain_stall_timeout_seconds}` (default-off), `wait_for_shutdown`
  `Duration`→`Option<Duration>`, `ServerHealth.drain` gating a 503, new `/drain_status` route. Tests:
  `--lib drain::`, `--lib server::tests::wait_for_shutdown_tests`, `--lib settings::tests`, `--lib
  health_check::` / `--lib drain_status::`. Real QUIC accept-loop refusal is left to manual/e2e (no
  mock-friendly seam).
- **CR-009 follow-up: gRPC-leg drain wiring [SERVER]** — `lore-server/src/server.rs`.
  `launch_grpc_server` now waits on `drain_state.wait_idle()` before tonic shutdown, mirroring
  `launch_http_server`'s existing pattern (public gRPC server previously tore down instantly on
  SIGTERM). No callable shutdown fn to unit test directly (inline `async move` at both call sites);
  covered by a `shutdown_signal` mirror added to `drain.rs::tests` (must live there, not
  `server.rs::tests` — see white-box gotcha below). Real cross-process SIGTERM behavior left to the
  desktop repo's live e2e that found the bug.
- **CR-010 `NotificationService.Subscribe` repo-authz cross-check [SERVER]** —
  `lore-server/src/grpc/notification_service.rs`. JWT interceptor authorizes the repo in request
  metadata; `subscribe` streams the repo in the request body — previously no cross-check. Fix:
  `verify_authorization(token, body_repository)` when an `AuthorizationToken` extension is present.
  `grpc::notification_service::tests`. Deny path verified via returned `Status` only — the
  `NotificationSender`'s internal `DashMap` is private and unreachable from a sibling test module.
- **CR-011 repository-scoped authz on RepositoryMetadataGet/Set [SERVER]** —
  v0 (`grpc/handlers/repository_metadata_{get,set}.rs`) + v1
  (`grpc/repository/v1/repository_metadata_{get,set}.rs`). `RepositoryService` rides an authn-only
  interceptor, so the repo id in the body was unauthorized upstream; all 4 handlers now re-check via
  `check_repository_query_authorization` (shared with the sibling read RPCs). 12 tests (deny +
  does-not-CAS proof, accept-own-repo, auth-off, per handler). Shared fixtures:
  `authz_test_support` in `repository_query.rs` (stub auth server + store/seed helpers — see gotchas
  below). `--lib -- repository_metadata`.
- **CR-015 lock/unlock fires `lorehub_notify` [SERVER]** — `hooks/traits.rs` (`HookPoint` +
  `ResourceLock`/`ResourceUnlock`), `hooks/lorehub_notify.rs` (`EventFields.lock_hash`, not serialized
  in `to_payload()` — wire shape unchanged), `grpc/lock_service.rs` (`hook_dispatcher` ctor arg,
  `lock`/`admin_lock`/`unlock` fire the new hook points). Coverage: `--lib -- hooks` (101 passed);
  `--lib -- grpc::lock_service` including a `hook_context` submodule that pure-function-tests the
  private `lock_hook_context` builder directly, rather than racing the detached `spawn_post` task.
- **WP-066 Part 1: `lorehub_notify.deliveries` OTel counter [SERVER]** —
  `lore-server/src/hooks/lorehub_notify.rs`. `Counter<u64>` labeled `event_type` + `outcome`, cached
  in a module-local `OnceLock`. **The counter itself is deliberately untested at the unit tier** — the
  process-wide `METER_PROVIDER` OnceLock makes swapping it per-test a cross-test isolation violation,
  and the instrument's `OnceLock` binds to whichever provider was active at *first-ever* construction
  (see gotchas below). Covered instead: `post_handler`'s `Result`-visible outcomes (2xx/non-2xx/
  unreachable) and a `reqwest::Error::is_timeout()` predicate test. `timeout` vs `transport_error`
  labels and `serialize_error` are left to manual/integration (scrape `/metrics`). `--lib --
  hooks::lorehub_notify` (16 tests). New client-code tests need a real listening socket
  (`TcpListener::bind` + `axum::serve`), not `axum_test::TestServer`'s in-process mock transport —
  we're testing our own HTTP client here, not a server.
- **WP-066 Part 2 (Chunk 2): bounded in-process retry [SERVER]** — same file. `post_handler` wraps the
  POST in a bounded retry (`lore_revision::util::time::{RetryPolicy, Retry}`): transport
  error/timeout or 5xx/429 retries with backoff, other 4xx/2xx is terminal. New
  `[hooks.lorehub_notify.retry]` config (`initial_backoff_ms`/`max_backoff_ms`/`max_attempts`/
  `jitter`), default 2 retries. `--lib -- hooks::lorehub_notify` (24 tests after a reviewer-pass
  follow-up adding 429 + zero-timeout-rejection cases). Test helper:
  `start_counting_stub_receiver<F: Fn(usize) -> StatusCode>` scripts per-attempt responses;
  `fast_retry_policy(max_attempts)` keeps retry tests near-zero wall time (only the deliberate
  default-policy test pays real backoff, proving the omitted-table path uses real defaults). A
  "transport-error-then-recovers" case was deliberately skipped — no clean way to script without
  either a rebind TOCTOU race or new raw-socket machinery; recovery is covered for the two
  response-code-driven cases (503, 429) instead.
- **CR-020 provider-neutral authentication refresh [CLIENT]** — `lore-proto::auth::UserToken`
  `refresh_token` field; UCS poll/external/refresh mapping; `lore-transport` 5-minute refresh window +
  orchestration; `lore-credential` per-identity OS-file lease with guarded authn/refresh replacement.
  `cargo test -p lore-transport --lib` (47), `cargo test -p lore-credential --lib` (29), plus
  `lore-revision --test auth --test auth_exchange` (7+8) as neighbor gates. Covers refresh-fallback
  identity/expiry/domain re-checks, cross-process nonce uniqueness (two child test processes),
  bounded-timeout behavior under a hung provider/wedged lock, and persist-before-publish (a failed
  guarded write must not corrupt the previously-cached pair).
- **CR-017 transport/auth reset + `Unauthenticated` classification [CLIENT]** — `lore-transport`:
  `src/error.rs` (`Unauthenticated` arm on `From<tonic::Status>`), `src/grpc/mod.rs`
  (`apply_refreshed_tokens` empty-overwrite guard, `drop_grpc_connections()` clearing the
  process-global `CONNECTION_MAP`), `src/auth/exchange.rs` (`clear_authz_cache()` clearing the
  process-global `AUTHZ_CACHE`). `cargo test -p lore-transport --lib` (33). Both process-global caches
  need per-test unique keys, not empty/size assertions (see gotchas below).
- **CR-018 QUIC write-permission enforcement [SERVER] + CR-019 push-time lock enforcement [SERVER]** —
  both default-off. CR-018: `quic/storage_service_v4.rs` (`require_write` gate on the
  `StorageCommand` dispatch) + legacy `quic/storage_service.rs`. Tests seed a session directly
  (white-box, not a minted JWT — `require_write` never re-verifies a token, only reads
  `permissions`/`jwt_verifier.is_some()`). CR-019: `grpc/handlers/push_lock_guard.rs`
  (`collect_push_lock_conflicts`) — real in-memory repo fixture via
  `RepositoryContext::new_server_context`, no wire/RPC layer needed; covers foreign-lock-on-changed-
  path, self-lock exempt, untouched-path exempt, empty-locks short-circuit (no diff attempted),
  branch-creation zero-hash case, and a rename catching both endpoints. **Known gap**: the v1
  `branch_push.rs` handler's own `lock_enforcement: Option<&Arc<dyn LockStore>>` is always called
  with `None` in every existing test — no test exercises `Some(lock_store)` end-to-end through the
  RPC handler, only the pure `collect_push_lock_conflicts` core.
- **CR-008 per-entry byte size on tree reads [SERVER]** — additive proto3 optional
  `TreeNode.size_bytes` (FILE only) + `Revision.total_size_bytes`; `lore-revision`'s
  `TreePath.size`; handlers `thinclient/v1/revision_tree.rs` + `revision_info.rs`. `--lib --
  thinclient::v1::revision_`. Per-file field verified with a real value; the aggregate only asserts
  `Some(0)`/`Some(_)` at unit tier (rollup requires the real commit pipeline — see gotcha below).
- **CR-021 Part 1: DynamoDB throttle/error-classification honesty [SERVER]** —
  `lore-aws/src/aws_error.rs` (`is_retryable_sdk_error`, explicit `RETRYABLE_STATUS_CODES` allow-list,
  `is_throttle_code`) + `store/immutable_store.rs` (`SlowDown` passthrough). Fixes a metadata-load
  throttle previously misclassified as `AddressNotFound` (masked a capacity problem, defeating
  `lore-revision`'s 10-attempt retry-on-`SlowDown`). `--lib -- aws_error::` (13, no store/mock) +
  `store::immutable_store::test::test_{load_metadata,query_metadata_load_slow_down_passes_through,
  metadata_load_error_non_sdk_error_is_internal}`. Rewrote one upstream-authored test that pinned the
  pre-fix bug — flag that rewrite explicitly in any eventual upstream PR.
- **CR-021 Part 2a: SDK-level adaptive retry/backoff config [SERVER]** — `lore-aws/src/clients.rs`.
  New `RetryMode` (`Standard` default / `Adaptive` opt-in / `Disabled`), `RetrySettings`, `impl
  From<&RetrySettings> for RetryConfig`. Closes a prior gap where every client silently used the SDK's
  bare 3-attempt default. `--lib -- clients::` (16, pure config-mapping, no network). Default is
  `Standard`, not `Adaptive` — see the adaptive-retry-latency gotcha below.
- **CR-021 Part 2b: application-level `SlowDown` propagation honesty [CLIENT-relevant, ships in
  lore-revision]** — `lore-revision/src/state.rs`'s `collect_new_addresses`. Narrowed 3 silent error
  swallows to propagate only `SlowDown` (top-level `query()`, fragmented payload's own `load_raw`,
  recursive child `collect_new_addresses_recurse`); `lore-server`'s `branch_push.rs::verify_fragments`
  maps propagated `SlowDown` → `ResourceExhausted`. `cargo test -p lore-revision --test state` (42) +
  `grpc::handlers::branch_push::tests`. One of the three swallows (own-fragment `get()`) is real in
  production but only reachable via a working remote session that itself returns `SlowDown` — not
  observable from a local-only fixture; the *swallow* (children silently missing from the `Ok`
  result) is independently testable and is what's pinned instead. See the SlowDown-propagation
  gotcha below for the full reasoning.
- **CR-021 Part 2c: read-layer controls [CLIENT]** — `lore-storage/src/read.rs`. Wraps a real
  `LocalImmutableStore`, injects `SlowDown` or a generic deserialize failure from `get()`.
  `SlowDown` is now preserved through the local-with-remote-fallback boundary (was previously
  normalized to `AddressNotFound` alongside genuine absence). `--lib -- read::tests::` +
  the `lore-revision --test state` swallow test above.
- **CR-016 `RepositoryStorageStats` [SERVER]** — new read-only RPC on
  `lore.repository.v1.RepositoryService`. `lore-storage`'s `StoreRepositoryStats` +
  `ImmutableStore::repository_stats` default method returning `NotSupported` (deliberate — avoids a
  hidden full-table scan on backends with no repo-keyed access path); only
  `lore-postgres::PostgresImmutableStore` overrides it, backed by a new
  `lore_fragments_repo_hash (repository, hash)` index. Handler re-checks authz via CR-011's callback,
  maps `NotSupported → Unimplemented`, `SlowDown → ResourceExhausted`. Coverage:
  `--lib -- grpc::repository::v1::repository_storage_stats` (8, reuses CR-011's
  `authz_test_support`); `lore-storage --lib -- immutable_store::tests::repository_stats_default` (1,
  pins the trait default via a real `LocalImmutableStore`); `lore-postgres --test immutable_store`
  (14, 4 new, gated on `LORE_TEST_PG_URL`/`LORE_TEST_S3_*`) covering unknown-repo-all-zero,
  multi-fragment sum, same-hash-two-contexts counted once, and cross-repo isolation. `lore-proto`'s
  hand-written proto-surface tests (`tests/v1_repository.rs`, field-shape destructuring) needed
  updating for the 7th RPC pair. Neither `ReplicatedStore` nor `GrpcReplica` overrides
  `repository_stats` — both silently inherit `NotSupported` under a composite/replicated topology
  even when the backend could answer; pinned with one test each against their existing mock
  fixtures. **Live-infra run** (Postgres 16 + MinIO via `docker run`, 50k fragments / 500 repos):
  `EXPLAIN (ANALYZE, BUFFERS)` confirmed `Bitmap Index Scan on lore_fragments_repo_hash` + `Index Scan
  using lore_fragment_metadata_pkey` — no sequential scan. Commands:
  ```
  docker run -d --name lore-pg-test -p 5433:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=lore postgres:16
  docker run -d --name lore-minio-test -p 9090:9000 -p 9091:9001 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data --console-address ":9001"
  ```

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

### Deterministic async & retry-timing tests
- **`#[tokio::test(start_paused = true)]` for anything driven by real timer ticks** (e.g.
  `lore-server`'s `drain` module's 1s loop / 250ms poll) — tokio auto-advances virtual time to the
  next timer once every task is blocked on one, no manual `advance()` needed; wrap awaited futures in
  `tokio::time::timeout(...)`. Needs the tokio `test-util` feature added as a crate-local
  `[dev-dependencies]` override (the workspace dep doesn't enable it) — without it you get a
  misleading `no method named 'start_paused'` from the macro expansion, not a clear "feature missing"
  error.
- **A `SlowDown`-injecting test can silently burn ~9 minutes of wall time** if it lets the real
  client retry policy run un-paused (`lore-storage::read::read_raw` defaults to 60 attempts,
  50ms→10s uncapped exponential backoff — deliberately patient for a real CLI, wrong for a unit
  test). Use `start_paused = true` the same way as above. Don't try to shrink the global
  `STORE_RETRY_ATTEMPTS` `OnceLock` from inside a test — it's process-wide and first-writer-wins,
  so a parallel test can beat your `.set(1)`. `lore-server`'s crate-level `#[ctor::ctor]` bootstrap
  already sets it once for the whole binary; that's the safe place for a crate-wide override.
- **Asserting a `tracing::warn!`/`info!` fired: `tracing_test::traced_test` + its macro-injected
  `logs_contain(&str)`**, not a hand-rolled subscriber. `#[traced_test]` above `#[test]` (or above
  `#[tokio::test]` for async). It scopes to the test's own span, so it stays isolated under the
  default multi-threaded runner.

### White-box access & fixture patterns
- **A same-file `#[cfg(test)] mod tests` gets private-field access to its parent**; a *sibling*
  module does not. Use it to fabricate otherwise-unconstructible states (e.g. poke a registry's
  atomic counter to simulate N active connections instead of needing a real handshake). If a
  shutdown/composition test conceptually "belongs" to a different file but needs a private field
  from another module, write the test in the module that owns the field, not where the behavior
  under test lives — don't add a `pub(crate)` test-only accessor to unblock the other direction
  without the delta author's sign-off.
- **gRPC-service unit tests need no live server.** Build a `tonic::Request::new(...)`, populate
  either `.metadata_mut()` (what the JWT interceptor would derive) or `.extensions_mut().insert(...)`
  (what handlers reading a token from extensions expect), then call the trait method directly on a
  directly-constructed service. `#[tokio::test]` is enough.
- **`Result::expect_err` won't compile on a streaming RPC response** (`Response<Pin<Box<dyn Stream +
  Send>>>` isn't `Debug`). Use `.err().expect("msg")` instead.
- **Wrap any stream-delivery assertion in `tokio::time::timeout(...)`.** A regression that silently
  drops an event would otherwise hang the test instead of failing fast — the default pattern for any
  "assert an event arrives on this stream" test.
- **Hand-rolling a stub gRPC *server* when the proto compiles `.build_server(false)`** (no generated
  server type to bind a fake to): implement `tonic::server::NamedService` + `tonic::codegen::
  Service<http::Request<B>>`, dispatch on `req.uri().path()` per-RPC via
  `tonic_prost::ProstCodec::default()` + `tonic::server::Grpc::new(codec).unary(...)`. Reuse
  `lore-server/src/grpc/handlers/repository_query.rs`'s `authz_test_support::StubAuthService`
  (`pub(crate)`) rather than re-deriving this.
- **Ephemeral-port test server: bind once, then `serve_with_incoming`/`axum::serve` on that same
  listener — never bind-read-port-drop-then-rebind.** The drop-then-rebind gap is a real TOCTOU
  (another process can grab the port) and invites masking the remaining startup race with a fixed
  `sleep`. `tokio::net::TcpListener::bind("127.0.0.1:0")`, read `local_addr()`, serve on that same
  socket in a detached spawn — it's already in the OS backlog as soon as `bind` returns.
- **A real store fixture for a handler test doesn't need a full repo checkout.**
  `LocalImmutableStore::new(None, ImmutableStoreSettings::default())` /
  `LocalMutableStore::new(...)` cover most `Arc<dyn ImmutableStore>`/`Arc<dyn MutableStore>`
  handler signatures directly; reach for `RepositoryContext::new_server_context` only to seed/read
  state before/after. `RepositoryMetadata`'s `READ_ONLY_KEYS` must stay byte-identical between
  `expected` and a proposed CAS blob or `validate_read_only_fields` rejects it before the CAS is even
  attempted.
- **Three `ImmutableStore` fault-injection fixture shapes — pick by call shape, don't invent a
  fourth:**
  1. *Canned-response fake, no backing store* (`lore-revision/tests/composite_store.rs`'s
     `TestStore`/`DelayStore`) — cheapest, but can't back anything that needs a real Merkle/state
     walk to read back correctly.
  2. *Unconditional-failure fake, no backing store* (`lore-server/src/lib.rs`'s
     `SlowDownImmutableStore`) — good for exactly one thing: proving a retry loop exhausts.
  3. *Wraps a real store, intercepts selectively* (`FaultInjectingStore` / `SlowDownQueryStore`) —
     delegates every method to a real inner store except an armable `query()`/`get()`. The only one
     that composes with real `node_add`/`serialize`/`deserialize`: build fixture state normally, arm
     the fault, then call the code under test.
- **A test module's mock must let a clone kept by the test observe the same state as the clone the
  code under test holds** when the code stores things by value (e.g. a connection registry). Wrap
  shared state in `Arc<AtomicU64>` counters rather than plain fields.

### Process-global state hazards
- **Any process-wide `OnceLock`/static shared across a crate's whole test binary is a test-isolation
  hazard** — same class of bug whichever crate it's in: `lore_telemetry::metrics::METER_PROVIDER`
  (an OTel instrument binds to whichever provider was active at *first-ever* construction; a later
  `set_meter_provider` doesn't rebind it), `lore-transport`'s `CONNECTION_MAP`/`AUTHZ_CACHE`, and
  Epic's own `hooks::dispatch.rs` panic-hook (`std::panic::set_hook` is process-wide — 4 of its own
  tests intermittently flake against each other, ~1-in-3 on this rig; confirmed unrelated to any of
  our hook deltas via `git stash`, not ours to fix). Rule: use a unique key per test (a distinct fake
  URL/cache key), assert only on that key's identity/absence, never on global size/emptiness — you
  can't prove a shared `OnceLock` is unset, only that repeated clear calls don't panic. If a solo run
  of a module containing one of these flakes red, re-run once and scope the real gate to the specific
  submodule your delta touches rather than treating the whole module as the pass/fail signal.

### AWS SDK specifics
- **AWS SDK exception builders don't populate `.code()` unless `.meta()` is set explicitly** —
  `SomeException::builder().build()` won't exercise code-based classification; you need
  `.meta(ErrorMetadata::builder().code("ExceptionName").build())`. Applies to any modelled service
  error, not just DynamoDB.
- **Adaptive retry's `ClientRateLimiter` is NOT bounded by `RetryConfig::max_backoff`.** Its
  token-bucket limiter can stall ~2s before the first attempt and ~10s per retry when drained,
  independent of `max_backoff`; with 5 max attempts that's worst-case ~42s — more than loreserver's
  flat 50s request-handler timeout. The limiter is also process-global per service client, so one
  tenant's throttling throttles every other tenant sharing that client. This is why `lore-aws`
  defaults `RetryMode` to `Standard`, not `Adaptive`. Verify behavior like this against the vendored
  SDK source (`cargo metadata` → find `aws-smithy-runtime`'s `manifest_path` → read
  `src/client/retries/`), not inferred from the builder API surface.
- **`RetryConfig::disabled()` is not a third `RetryMode` — it's `standard().with_max_attempts(1)`**,
  which silently discards a caller's own `max_attempts`/backoff settings. `lore-aws`'s own
  `RetryMode::Disabled` maps through an early `return RetryConfig::disabled()`; intentional, pin the
  exact resulting shape rather than assuming configured overrides apply.
- **Which `clippy.toml` governs a crate is per-crate, not workspace-uniform.** The workspace-root
  `clippy.toml` bans raw `tokio::spawn`; a crate with its own `clippy.toml` that doesn't repeat that
  list (e.g. `lore-server/clippy.toml`, which only sets `future-size-threshold`) shadows the parent
  entirely rather than merging with it. `lore-postgres` has no `clippy.toml` of its own, so it
  inherits the root ban and needs `lore_base::lore_spawn!` even for test-only raw-connection I/O.
  Don't assume a pattern that passes clippy in one crate is safe to copy into another without
  checking which `clippy.toml` (if any) actually applies there.

### Known test-tier limitations
- **A rollup/aggregate field sourced from the real commit pipeline reads back as its zero value in a
  flat handler-unit-test fixture**, even with real per-node data present — e.g. `Revision.
  total_size_bytes` (`state.tree(repo).await?.size`) stays `Some(0)` when a test builds a revision
  via `State::new()` + raw `node_add`/`serialize` without driving staging/commit, because the rollup
  only happens in `commit.rs`'s `rehash_directory_recurse` → `State::update_tree_root_hash`. Setting
  a *per-node* field (e.g. `node.size`) directly on the literal before `node_add` is fine; don't try
  to fake an *aggregate* with low-level writes — assert the plumbing invariant only (`Some(_)` /
  `Some(0)`) and defer the real rollup to an integration/e2e tier.
- **When a propagation path is structurally unreachable from a local-only fixture, check whether the
  underlying *swallow* is independently testable before flagging the whole thing as an untestable
  gap.** A `SlowDown` from a fragmented payload's own `get()` can't be observed propagating through
  `load_raw`'s local-with-remote-fallback boundary using a no-remote-session fixture (the fallback
  normalizes every local failure type to `AddressNotFound`/`NoRemote` before it reaches the caller) —
  but whether the addresses go **missing from the `Ok(_)` result** (the actual integrity question) is
  observable with the same fixture already built for the propagation attempt: arm `get()` to fail,
  then assert on what's absent from the result instead of asserting on `Err`. The assertion that
  matters to a reader is usually "did data silently vanish," not "did an error come back" — check for
  that angle before writing off a case as untestable.

## Appending new findings

This file holds durable, generalizable lessons only — not a chronological log. Chronology lives in
`docs/worklogs/` (the `worklog-scribe` close-out lane). Only add something here if it's a lesson
likely to recur across future work. Keep it terse — a few lines, grouped under the closest existing
theme above (or a new one if none fits) — and skip one-off narrative entirely; it doesn't belong here
beyond the worklog entry that already covers it.
