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
  endpoint is required. The required `ImmutableStore::get_metadata` implementation delegates to the
  same full metadata query as `query(..., MatchFull)`; the live
  `get_metadata_returns_the_stored_fragment_and_full_match` integration test pins the stored
  fragment and `MatchFull` result and remains honestly `#[ignore]`d without Postgres + S3.
- **lore-aws (S3-authoritative fragment metadata + global state)** — `lore-aws/src/store/`.
  Upstream 0.8.7 retired the fork's unused `DynamoBucketResolver` and
  `DedupScope::Partition`; fragment representation now travels in S3 object metadata and DynamoDB
  keeps only global lifecycle state plus repository/context associations. Unit tests run fully
  offline against the stateful `Fake` + mocked SDK clients. The direct
  `head_fragment_error_permanent_service_error_is_internal` and
  `get_payload_error_permanent_service_error_is_internal` controls pin that permanent S3 service
  errors are `Internal`, never missing or retryable; run
  `cargo test -p lore-aws --lib permanent_service_error -j 4`.
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
- **CR-011 (repository-scoped authz on RepositoryMetadataGet/Set, [SERVER])** —
  `lore-server/src/grpc/handlers/repository_metadata_{get,set}.rs` (v0) and
  `lore-server/src/grpc/repository/v1/repository_metadata_{get,set}.rs` (v1). `RepositoryService`
  rides the authn-only `JWTAuthnInterceptor` (UCS-13506), so the repository id in the request body
  was never authorized upstream; all four handlers now re-check it via
  `check_repository_query_authorization` (the same ReBAC callback the sibling read RPCs use,
  `lore-server/src/grpc/handlers/repository_query.rs`) before any store read/CAS, gated on
  `auth_url: Option<String>` (auth-OFF is a no-op). 12 tests, 3 per handler (deny + does-not-CAS
  proof, accept-own-repo, auth-off) in each handler's own `#[cfg(test)] mod tests` (v1 set nests its
  new `mod authorization` alongside the pre-existing `mod validate_read_only_fields`, untouched).
  The own-repo accept case is the headline: it's the proof that a legitimate stock-`lore`-CLI client
  operating on its own repository is unaffected. Deny cases additionally seed a well-formed,
  would-succeed CAS payload and re-read `repository::metadata_hash` after the denial to prove the
  CAS never ran, not just that the handler returned an error. `check_repository_query_authorization`'s
  `Unauthenticated`-remap branch is untested (the stub server only ever returns `Ok` or
  `PermissionDenied`) — deferred, not a one-liner to add. Shared fixtures:
  `authz_test_support` in `repository_query.rs` (stub auth server + store/seed helpers — see the
  two "Deep findings" entries below for the reusable technique).
  `cargo test -p lore-server --lib -- repository_metadata` (23 tests: 12 new + 10 pre-existing
  `validate_read_only_fields` + 1 unrelated substring match).
- **CR-015 (lock/unlock fires `lorehub_notify`, [SERVER])** — three files: `hooks/traits.rs`
  (`HookPoint` gained `ResourceLock`/`ResourceUnlock`, `all()` now length 7),
  `hooks/lorehub_notify.rs` (`HOOK_POINTS`/`event_type()` extended; `EventFields.lock_hash: Option<String>`
  sourced from `ctx.get_metadata("lock_hash")`, folded into `event_id()` as a trailing segment but
  **not** serialized in `to_payload()` — wire shape unchanged), and `grpc/lock_service.rs`
  (`LoreLockService` gained a 3rd ctor arg `hook_dispatcher: Arc<HookDispatcher>`; `lock_as_user` gained
  a trailing `correlation_id: &str`; new private fn `lock_hook_context(...)` builds the
  `HookContext` with `metadata` keys `lock_hash`/`lock_description`; `lock`/`admin_lock`/`unlock` call
  `hook_dispatcher.spawn_post(HookPoint::ResourceLock|ResourceUnlock, lock_hook_context(...))`).
  Coverage: `cargo test -p lore-server --lib -- hooks` (101 passed, was 98 pre-CR-015 — 3 new:
  `lock_hash_disambiguates_event_id_for_same_second_same_repo`,
  `revision_event_id_unaffected_by_absent_lock_hash`,
  `lock_payload_matches_contract_shape_and_omits_lock_hash`); `traits::tests` updated for the 7-variant
  `all()`/`Display`; `cargo test -p lore-server --lib -- grpc::lock_service` (13 passed) including a
  new `grpc::lock_service::test::hook_context` submodule that pure-function-tests the private
  `lock_hook_context` builder directly (context fields + the two metadata keys) — chosen over asserting
  the fire-and-forget `spawn_post` end-to-end, since that's a detached `lore_spawn!` task with no join
  handle (would need a sleep-based race to observe). **Gotcha:** every one of the ~8
  `LoreLockService::new(...)` call sites in that file's `#[cfg(test)] mod test` needed the new 3rd arg
  inserted (`Arc::new(crate::hooks::HookDispatcher::empty())`, mirroring `branch_delete.rs`'s pattern) —
  a `replace_all` Edit on the common `notification_sender,\n  Duration::from_secs(60),\n  false,`
  tail handled 7 of 8; the 8th (`permission::make_service`, using `enforce` not a literal `false`)
  needed its own edit. **`cargo +nightly fmt --all -- --check` flags pre-existing impl code, not test
  code, here:** CR-015's own `lock_as_user` (lines ~178-186, the `self.hook_dispatcher.spawn_post(...)`
  call wrapping `lock_hook_context(...)`) is itself not nightly-fmt-clean — a real gap in the
  implementation commit, reported back rather than reformatted (out of test-code scope). Confirmed via
  `cargo +nightly fmt --all -- --check` showing only that one `Diff in ... lock_service.rs:178/186`
  after all test-code edits were applied.
- **WP-066 Part 1 (`lorehub_notify.deliveries` OTel counter, [SERVER])** —
  `lore-server/src/hooks/lorehub_notify.rs`. A `Counter<u64>` (`urc.hooks.lorehub_notify.deliveries`,
  labels `event_type` + `outcome` ∈ `success|http_error|transport_error|timeout|serialize_error`),
  built via `lore_telemetry::InstrumentProvider` and cached in a module-local `OnceLock`
  (`LorehubNotifyInstruments::instance()`, mirrors `util/cert_metrics.rs`); `record_delivery(...)`
  called at all 5 terminal sites in `post_handler`. **The counter itself is deliberately left
  untested at the unit tier** — decided not to force it, for two compounding reasons found while
  investigating:
  1. `lore_telemetry::metrics::METER_PROVIDER` (`lore-telemetry/src/metrics/mod.rs:27`) is a
     **process-wide** `OnceLock<RwLock<Arc<SdkMeterProvider>>>`, not per-test/per-thread — it's
     `lore-server`'s own indirection layer in front of OTel (NOT `opentelemetry::global`), shared by
     `cargo test -p lore-server`'s single test binary across every module. Swapping it to an
     in-memory reader (`opentelemetry_sdk`'s `testing` feature — already a `[dev-dependencies]`
     entry, `lore-server/Cargo.toml:90`, so no new dep needed) for one test would rebind whichever
     other concurrently-running test's instrument happens to be first-constructed after the swap too
     — a real shared-mutable-global-state test-isolation violation (`lore/CLAUDE.md` "Tests must be
     independent/isolated"), not a one-line fix.
  2. Even ignoring that, `LorehubNotifyInstruments::instance()`'s `OnceLock` binds the `Counter` to
     whichever `SdkMeterProvider` was active at **first-ever** construction in the process — a later
     `set_meter_provider` call doesn't rebind an already-built instrument. Since nothing else in
     `lore-server` currently calls `record_delivery`/`post_handler`, a test-first swap is
     order-dependent (works today only because no other test races it) and would silently stop
     working the moment a second test anywhere touches this hook — a fragile invariant to build a
     real assertion on.
  - What's covered instead: `post_handler`-level behavior tests for the 3 outcomes distinguishable
    via its **returned `Result`** (the POST's error-return behavior, unchanged by this delta) —
    `post_handler_succeeds_and_records_success_on_2xx` (real ephemeral-port `axum::serve` stub
    returning 200 → `Ok`), `post_handler_errors_and_records_http_error_on_non_2xx` (500 → `Err`
    containing the status), `post_handler_errors_and_records_transport_error_when_unreachable`
    (bind-then-drop a port → `Err` containing `"post:"`). Plus one predicate-level test,
    `reqwest_is_timeout_distinguishes_timeout_from_connection_refused`, that empirically confirms
    `reqwest::Error::is_timeout()` — the exact boolean `post_handler`'s `outcome` classification
    branches on — reads `false` for connection-refused and `true` for a held-open,
    never-responding connection (300 ms client timeout; stable across repeat local runs). The
    `timeout` vs `transport_error` **label** split itself is NOT independently verifiable this way
    (both produce an identical `Err` shape from `post_handler` — the distinction is only visible in
    the counter), and `serialize_error` is practically unreachable (the `Value` here is built from
    known-finite strings/`Option<u64>`, so `serde_json::to_vec` doesn't fail in practice) — both left
    to manual/integration verification (e.g. scraping `/metrics` against a real dev stack). Coverage:
    `cargo test -p lore-server --lib -- hooks::lorehub_notify` (16 tests, was 12 pre-WP-066).
  - **Gotcha — new tests need a real listening socket for `reqwest` to connect to**, not
    `axum_test::TestServer`'s default in-process mock transport (used everywhere else in
    `lore-server` for handler tests, e.g. `http/health_check.rs`) — that only works because those
    tests exercise the *server* side. Here we're testing our own HTTP *client* code, so the receiver
    needs a real port: `tokio::net::TcpListener::bind("127.0.0.1:0")` + `axum::serve(listener, app)`
    in a `tokio::spawn`, mirroring `repository_query.rs::authz_test_support::start_stub_auth_server`'s
    bind-then-serve pattern (no drop-rebind TOCTOU, no readiness sleep — socket is already in the OS
    backlog when `bind` returns). For the deliberately-unreachable case, bind-then-**drop** (opposite
    of that pattern) is the right tool — we want the port empty so the connection is refused; tiny
    accepted TOCTOU risk (another process could theoretically grab the port first).
  - **Gate note:** `cargo +nightly fmt --all -- --check` on this file flags 2 diffs in the
    **implementation** (not test) code added by this same delta — `lorehub_notify.rs:295` (the
    `serialize_error` `Err` arm) and `:320` (the `outcome = if e.is_timeout() {...}` binding) are not
    nightly-fmt-clean. Reported back rather than reformatted (out of test-code scope), same pattern
    as the CR-015 gotcha above.
- **WP-066 Part 2 / Chunk 2 (`lorehub_notify` bounded in-process retry, option C,
  [SERVER])** — same file, `lore-server/src/hooks/lorehub_notify.rs`. `post_handler` now
  wraps the POST in a bounded retry loop over `lore_revision::util::time::{RetryPolicy,
  Retry}`: a transport error/timeout OR a 5xx/429 is always retried (with backoff); any
  other 4xx (or a 2xx) is terminal. The signed body + timestamp are computed **once**
  and reused across attempts (raw_body is cloned per attempt) so the receiver dedups a
  retried POST on `event_id`. New optional `[hooks.lorehub_notify.retry]` sub-table →
  `RetrySettings` (`initial_backoff_ms`/`max_backoff_ms`/`max_attempts`/`jitter`);
  omitted → `DEFAULT_RETRY_LIMIT` = 2 retries, 200 ms→2 s backoff. `LorehubNotifyHook`
  gained a `retry_policy: RetryPolicy` field (any direct struct-literal construction in
  tests needs it — `RetryPolicy` is `Copy`, so `self.retry_policy.retry()` behind `&self`
  is fine). Coverage: `cargo test -p lore-server --lib -- hooks::lorehub_notify` (22
  tests, was 16 pre-Chunk-2) —
  `post_handler_recovers_after_transient_5xx_then_succeeds` (503×2 then 200 → `Ok`, exact
  attempt count asserted, the headline behavior this chunk adds),
  `post_handler_fails_fast_on_4xx_with_no_retry` (exactly 1 request),
  `post_handler_exhausts_retries_and_errors_on_persistent_5xx` (`max_attempts + 1`
  requests then `Err`), `factory_builds_hook_from_valid_retry_table` /
  `factory_rejects_malformed_retry_table` (config parse), plus two end-to-end-through-
  the-factory behavior tests — `factory_built_hook_honors_configured_retry_table_attempt_count`
  and `factory_built_hook_uses_default_retry_policy_when_retry_table_omitted` — that go
  through `LorehubNotifyHookFactory::create` (a real `toml::Value`) rather than a direct
  struct literal, then call `.post_handler(...)` straight on the returned `Box<dyn Hook>`
  (no downcast needed — `Hook::post_handler` dispatches fine through the trait object),
  proving the parsed `[retry]` table / its absence actually thread through to observed
  attempt counts. The default-policy test pays ~0.5-1s of *real* backoff wall-time
  (deliberate — it's proving the factory's omitted-table path uses the real defaults,
  not a hardcoded assertion against the constants) — the only test in the file that
  isn't near-zero-backoff.
  - **Gotcha — request-counting stub receiver.** Existing ephemeral-port stub
    (`start_stub_receiver`, always-same-status) can't observe attempt counts. Added
    `start_counting_stub_receiver<F: Fn(usize) -> StatusCode>(respond)` — axum handler
    closure wraps an `Arc<AtomicUsize>` call counter, calls `respond(idx)` with the
    0-based call index so a test can script "503, 503, 200" etc., and returns
    `(url, Arc<AtomicUsize>)` so the test asserts the final count after `post_handler`
    returns. `start_stub_receiver` is now a 1-line wrapper over this that ignores the
    counter.
  - **Gotcha — keep retry-exercising tests fast.** A `fast_retry_policy(max_attempts)`
    helper builds `RetryPolicy` with `initial_backoff_ms = max_backoff_ms = 1` so tests
    that actually retry (recovery/exhaustion/transport-error) don't pay real backoff
    wall-time; only the deliberate default-policy test uses the real constants.
  - **Gate note (same pattern as CR-015/WP-066 Part 1):** `cargo +nightly fmt -p
    lore-server -- --check` flags one diff in **implementation** code added by this same
    delta — `lorehub_notify.rs:381-386` (the `let retryable = status.is_server_error() ||
    ...` binding wraps differently under nightly rustfmt). Reported back, not
    reformatted (out of test-code scope). **Fixed** in a follow-up (reviewer pass) — now
    fmt-clean.
  - **Follow-up (reviewer pass) — 3 more cases, 24 tests total:**
    `post_handler_retries_429_then_succeeds` (429 is a distinct predicate in
    `post_handler` — `status == TOO_MANY_REQUESTS`, not `is_server_error()` — covered
    separately rather than assumed to share the 5xx branch); `factory_rejects_zero_timeout`
    (the factory now rejects `timeout = 0` — reviewer-driven impl fix); positive-timeout-
    still-builds was already covered by `factory_builds_hook_from_valid_config`
    (`timeout = 5`), not re-added.
  - **Skipped, on purpose: a "transient transport-error-then-recovers" case.** Asked for
    but not added — genuinely awkward to script without introducing real flakiness, two
    approaches considered and rejected:
    1. *Port-rebind* (drop the listener so the port refuses, then re-bind the same port
       once "the handler comes up"): needs a second task to race the retry loop's own
       backoff sleep to rebind in the window between attempts — timing-sensitive, and
       exactly the drop-then-rebind TOCTOU pattern this guide already warns against
       ("Ephemeral-port test server: bind once..." finding above).
    2. *Raw-socket half-open* (accept then immediately drop the socket for the first N
       connections to force a real `ECONNRESET`, then hand off to a real HTTP responder
       for the rest, all on one already-bound listener — no rebind race): mechanically
       sound but needs either hand-rolled HTTP/1.1 framing or a new direct `hyper`
       dev-dependency (not currently in `lore-server/Cargo.toml`; axum wraps it but
       doesn't re-export it) — more test-only machinery than the assertion is worth, and
       still not risk-free (RST timing vs. reqwest's connection pool/retry-on-connect
       behavior isn't fully controllable from the test side).
    What *is* covered instead for the transport-error path: persistent unreachable-port
    (`post_handler_errors_and_records_transport_error_when_unreachable`, retries then
    errors) and the `is_timeout()` predicate itself
    (`reqwest_is_timeout_distinguishes_timeout_from_connection_refused`). The *recovery*
    half of "transport error retried, then succeeds" is asserted at the unit-test tier
    only for the two response-code-driven cases (503, 429); a transport-level recovery
    is structurally the same code path (`Err(e) if !terminal => retry.wait() then
    continue`) and would need an integration/e2e tier with a real bounce-able backend to
    add without flake risk — flag if wanted there.
- **CR-020 (provider-neutral authentication refresh, [CLIENT])** —
  `lore-proto::auth::UserToken.refresh_token` field 5; UCS poll/external/refresh shared
  response mapping and empty-request sensitive bearer call; `lore-transport` five-minute
  refresh window plus repository/custom-resource orchestration; and `lore-credential`
  per-identity OS-file lease with guarded authn/refresh pair replacement. Coverage:
  `cargo test -p lore-transport --lib` (47 passed) includes exact lead boundaries,
  no-call before the window, absent credential, successful replacement, transient/rejected/
  invalid response preservation while valid, login-required after expiry, both exchange
  paths, empty returned `UserToken`, exact RPC path, and sensitive bearer metadata;
  `cargo test -p lore-credential --lib` (29 passed) includes old-format serde, atomic pair
  commit, preserve-on-no-replacement, intervening-login supersession, different-identity
  independence, same-identity waiter reread, ordinary drop release, and real child-process
  exit release. Neighbor gates: `cargo test -p lore-revision --test auth --test
  auth_exchange` (7 + 8 passed), and test-target Clippy for both touched crates.
  **Gotcha:** `UcsAuthentication::connect_client` deliberately forces HTTPS with native
  roots, so unit tests should not weaken transport or install a machine root merely to
  observe the RPC. Pin the generated client's exact method path with a tiny
  `tower::Service<Request<tonic::body::Body>>`, and test the empty request, sensitive
  metadata, operation-specific missing-response helper, and shared wire mapping separately
  in `lore-transport/src/auth/ucs_auth.rs::tests`.
  **Safety regression:** refresh fallback must re-check a post-lease token's identity,
  expiry, and recipient domains. `auth::exchange::tests::*wrong_remote*` replaces the
  on-disk pair after the caller obtained a remote-appropriate token, then proves missing
  provider, RPC failure, and invalid refresh never return the reloaded wrong-remote token;
  the caller token wins while valid and the result is empty after it expires.
  **Cross-process nonce regression:** `concurrent_stale_process_caches_reserve_unique_encryption_nonces`
  starts two child test processes, warms both AES-GCM caches before releasing them together,
  and proves the ciphertext nonce prefixes differ and both payloads decrypt. This catches
  process-local counter allocation that passes same-process concurrency tests.
  **Bounded refresh regression:** `never_completing_provider_times_out_to_still_valid_original_token`
  and `held_refresh_lease_times_out_to_still_valid_original_token` use injected 20 ms
  provider/lease deadlines under an outer one-second timeout, proving neither a hung backend
  nor a wedged lock blocks normal use of the caller's still-valid token. The held-lease case
  then drops the original holder and reacquires the same identity under another one-second
  bound, proving the timed-out detached blocking waiter does not retain a ghost file lock.
  **Login pair-store regression:** `store_authentication_token_*` covers initial authn +
  supplied refresh storage, replacing both supplied credentials together, and updating
  authn with `None` while preserving the existing refresh credential. Login orchestration
  has no focused failure-injection seam; its existing `auth` / `auth_exchange` integration
  suites are retained as compile/dispatch regression gates (7 + 8 passed).
  **Persist-before-publish regression:** `failed_authentication_pair_write_keeps_previous_cached_pair`
  and `failed_refresh_commit_keeps_previous_cached_pair` seed an old pair, replace
  `tokens.toml` with a directory to force the guarded write to fail, capture in-process
  loads, restore the file, then assert both cached authn and refresh values remained old.
  Restore before assertions so even a regression does not contaminate later tests.
- **CR-017 (transport/auth reset + Unauthenticated classification, [CLIENT])** — three
  `lore-transport` files, none had a `#[cfg(test)] mod tests` before this delta:
  `src/error.rs` (new `Unauthenticated` arm on `From<tonic::Status> for ProtocolError`),
  `src/grpc/mod.rs` (`apply_refreshed_tokens` refresher empty-overwrite guard +
  `drop_grpc_connections()` clearing the process-global `CONNECTION_MAP` gRPC-cache), and
  `src/auth/exchange.rs` (`clear_authz_cache()` clearing the process-global `AUTHZ_CACHE`).
  Coverage: `cargo test -p lore-transport --lib` (33 passed, was 22 pre-CR-017) —
  `error::tests::{unauthenticated_status_maps_to_not_authenticated (ffi 12),
  unavailable_status_maps_to_disconnected (ffi 6, regression pin),
  unmapped_status_falls_back_to_internal (ffi -1)}`;
  `grpc::tests::apply_refreshed_tokens_*` (5 cases: both-empty/both-non-empty/mixed×2/
  empty-over-empty, plain `#[test]` against a bare `parking_lot::RwLock<GRPCAuth>` — no
  runtime needed since the fn under test is sync) and
  `grpc::tests::drop_grpc_connections_{clears_seeded_entry,is_noop_when_map_absent}`
  (`#[tokio::test]`, via the private same-module `lock_connection`);
  `auth::exchange::tests::clear_authz_cache_{evicts_seeded_entry,is_noop_when_never_populated}`
  (`#[tokio::test]`, via the private same-module `cache()` accessor).
  `connection.rs::drop_connections()`'s own restructure (runs the grpc-cache + authz-cache
  clears even when its pool map is already empty) was left to existing coverage — it calls
  `runtime().block_on` via `block_in_place`, needing a multi-thread runtime to test directly,
  and the two callees it now unconditionally invokes are independently covered above.
  **Gotcha — process-global statics, assert on your own key, not on size/emptiness.**
  `CONNECTION_MAP` (`grpc/mod.rs`) and `AUTHZ_CACHE` (`auth/exchange.rs`) are both
  process-wide `OnceLock`s shared across every test in the `lore-transport` test binary —
  same class of hazard as `lore-server`'s `METER_PROVIDER`/`dispatch.rs` panic-hook findings
  below, just in this crate. Use a unique key per test (a distinct fake URL like
  `http://cr017-test-host-a:41337`, or a distinct cache-key tuple) and assert only on that
  key's identity/absence; never assert the global map is empty or a particular size. The
  "no-op when never populated" cases can't actually prove the `OnceLock` is unset (another
  test may have already initialized it) — they instead prove calling the clear fn twice in a
  row (second call always finds an empty/already-cleared state) doesn't panic, which is the
  meaningful invariant anyway.
- **CR-009 follow-up: gRPC-leg drain wiring, [SERVER]** — `lore-server/src/server.rs`.
  `launch_grpc_server` gained `drain_state: Arc<DrainState>, graceful_drain: bool` params; its
  tonic shutdown future now does `shutdown_rx.wait_for(...).await; if graceful_drain {
  drain_state.wait_idle().await; }` before letting tonic begin graceful shutdown — mirroring
  `launch_http_server`'s pre-existing identical pattern (that one was already wired to
  `DrainState`; the public gRPC server previously wasn't, so it tore down ~instantly on SIGTERM
  and could sever a push's finalizing `branch_push` RPC mid-QUIC-drain). No implementation
  changes made for this delta (test-only pass). **No dedicated unit test for `launch_grpc_server`
  itself** — same as `launch_http_server`, its shutdown future is inline (an `async move` block
  passed straight into `.serve(...)`), not a named/callable fn, so neither call site has one.
  Instead, `lore-server/src/drain.rs::tests` (NOT `server.rs::tests` — see gotcha below) gained
  a `shutdown_signal` test-only mirror of the exact composition plus 4 tests pinning its shape:
  `shutdown_signal_does_not_resolve_before_shutdown_fires`,
  `shutdown_signal_resolves_immediately_when_graceful_drain_is_off`,
  `shutdown_signal_with_graceful_drain_and_zero_active_resolves_promptly`,
  `shutdown_signal_with_graceful_drain_waits_for_active_then_resolves`.
  `cargo test -p lore-server --lib -- drain::` (21 tests, was 17). Real cross-process SIGTERM
  behavior (does the actual gRPC listener answer `branch_push` mid-drain) is left to the live
  e2e in the desktop repo that found the bug in the first place — no mock-friendly seam for that
  tier either, same call as CR-009's own QUIC-endpoint note above.
- **CR-018 (QUIC write-permission enforcement, [SERVER]) + CR-019 (push-time lock
  enforcement, [SERVER])** — both default-**off**; this pass closed the review-flagged gap
  that only pure/unit logic had coverage, with no test exercising the actual DENY path at
  the handler seam.
  - **CR-018** — `lore-server/src/quic/storage_service_v4.rs` (`StorageServiceV4::require_write`,
    gating `Put`/`Copy`/`MutableStoreOp`/`MutableCas`/`Verify(heal)` in the `StorageCommand`
    dispatch match) and the legacy `lore-server/src/quic/storage_service.rs`
    (`StorageService::require_write`, same gate but reading the verified
    `AuthorizationToken` out of the connection `AttributeMap` instead of a session, since
    urc/0.2 has no session concept). New tests:
    `cargo test -p lore-server --lib -- quic::storage_service_v4::tests::require_write_dispatch_gate`
    (4: read-only denied, write allowed, enforcement-off bypass, auth-off bypass — all via
    `MutableStoreOp`) and
    `cargo test -p lore-server --lib -- quic::storage_service::tests::require_write_fails_closed`
    (3: missing-repository-and-token, missing-token-only, enforcement-off bypass).
    **v4 white-box seeding, not a minted JWT**: `require_write`'s gate only reads
    `self.jwt_verifier.is_some()` (a bool, "is a verifier configured") + the session's
    already-snapshotted `permissions` — it never re-verifies a token (that already happened
    once, at `AuthorizeStart`). So tests seed a session directly via
    `service.session_map.start(repo, corr, user, permissions)` (private field, reachable
    because `tests` is a same-file child module — the guide's existing "White-box state"
    finding) instead of round-tripping a real JWT through `AuthorizeStart`. `jwt_verifier`
    still needs to be `Some(..)` to represent "a verifier is configured" (`has_verifier`),
    so both files add a `JWKService` impl (`UnusedJwkService`) whose `get_key` is
    `unreachable!()` — proof the seeded-session path never calls it. Wire payload for a
    `MutableStoreOp` `StorageCommand` is `key(32) + value(32) + key_type(1)` — mirrors
    `mutable_store_handler.rs::tests::test_parse`'s own byte layout exactly; reuse that
    shape rather than re-deriving it (`Put`'s wire format is heavier: needs
    `lore_revision::fragment::generate_random()` + `validate_fragment_metadata` to pass,
    so prefer `MutableStoreOp` for gate-only tests where the specific opcode doesn't matter).
    v0's `require_write` fails closed at two independent points (missing `RepositoryId` →
    `NotConnected`; `RepositoryId` present but no `AuthorizationToken` → `AuthorizationFailure`)
    — both covered as distinct cases, not collapsed into one "context missing" test, since
    they're different code paths inside the same fn.
  - **CR-019** — `lore-server/src/grpc/handlers/push_lock_guard.rs`
    (`collect_push_lock_conflicts`, `pub(crate)`). New tests in a nested
    `collect_push_lock_conflicts_tests` submodule (kept separate from the pre-existing
    `others_locks_by_hash`-only tests one level up):
    `cargo test -p lore-server --lib -- grpc::handlers::push_lock_guard` (8: the 2
    pre-existing `others_locks_by_hash` cases + 6 new) — foreign lock on the changed path
    is a conflict, self-lock is not, a lock on an untouched path is not (guards against
    "any foreign lock blocks" over-broadening), the empty-foreign-locks short-circuit
    returns `Ok(empty)` **without attempting the diff** (proved by passing a
    never-serialized revision hash that would surface as `Err` if the diff ran), the
    branch-creation case (no prior tip → zero hash → diff against the empty tree still
    catches a locked new file — see `branch::load_latest`'s zero-hash-when-no-revision-yet
    behavior), and a rename catching both endpoints.
    **Real repo fixture, no wire/RPC layer needed**: build via
    `RepositoryContext::new_server_context` over `test_store_create()`'s in-memory
    `LocalImmutableStore`/`LocalMutableStore`, `branch::create` for the branch, and
    `state::State::new()` + `state.node_add(repo, ROOT_NODE, node, name)` +
    `state.serialize(repo, &write_token)` to build revisions — mirrors
    `grpc/revision/v1/branch_push.rs::test`'s `create_root_branch`/`build_revision`
    helpers (referenced from the task spec) rather than the heavier
    `grpc/thinclient/v1/revision_tree.rs::push_branch_with_revisions` pattern, since
    `collect_push_lock_conflicts` only needs `Hash`es and a `RepositoryContext`, not a
    tonic `Request`/RPC handler. **`push_revision` (via
    `crate::grpc::handlers::branch_push::push`, the v0 push fn — reusable regardless of
    which RPC generation actually lands a revision) establishes the *prior tip* only.**
    The revision being tested as the incoming push is built with `state.serialize(...)`
    alone and deliberately **not** pushed — `collect_push_lock_conflicts` diffs the
    about-to-be-pushed revision against the branch's *current* tip, which is exactly the
    state before `push()` would advance it (see the fn's own doc comment); pushing the
    second revision too would silently make `load_latest` return the wrong "prior" tip.
    **Rename fixture — match on `Node.address.context`, not content hash.**
    `detect_and_coalesce_moves` (`lore-revision/src/state.rs:4296`) coalesces an add/delete
    pair into a `Move` when their `Address.context` (the node/file-identity field, public,
    `lore_base::types::Context` — the same type alias as `BranchId`, so
    `random::<Context>()` works) matches and is non-zero; it does **not** compare content
    hash. Build two revisions with the same explicit `Context` at different paths (helper:
    `serialize_file_revision_with_context`) to get a real coalesced rename with
    `NodeChange.from_path` set, without needing any actual file-content plumbing.
    **The v1 `branch_push.rs` handler's own `lock_enforcement: Option<&Arc<dyn LockStore>>`
    param is still always called with `None` in every existing test** (`grep -n
    lock_enforcement lore-server/src/grpc/revision/v1/branch_push.rs` — one `if let
    Some(...)` call site, zero `Some(...)` call sites in tests) — i.e. the full RPC-level
    wiring of CR-019 (not just `collect_push_lock_conflicts` itself) has no test exercising
    `Some(lock_store)` end-to-end through `handler(...)`. Left as-is per the task's explicit
    scope (test `collect_push_lock_conflicts` directly, the "pure core" the fn's own doc
    comment calls out); flagged here as a real remaining gap if a future pass wants the
    full-handler-level proof too.
- **CR-008 (per-file byte size on tree reads, [SERVER])** — upstream 0.8.7's thin proto now carries
  proto3 optional `TreeNode.size` at tag 4 (including present zero), `TreeNode.mode` at tag 5, and
  retains fork-local optional `Revision.total_size_bytes` at tag 11 on `lore.thin_client.v1`.
  Lorehub preserves its existing tag-4 product contract by emitting size only for FILE nodes;
  DIRECTORY and LINK nodes remain unset even though Lore tracks their raw/aggregate sizes internally.
  `lore-proto/tests/v1_thin_client.rs` pins the generated field shape and exact wire bytes for all
  three tags; run `cargo test -p lore-proto --test v1_thin_client -j 4`. The handler tests remain in
  the existing `#[cfg(test)] mod test` blocks:
  `revision_tree.rs` — size reflection including a 0-byte file distinct from unknown, plus
  directory/link behavior; fixture `push_branch_with_sized_files` sets `node.size` directly.
  `revision_info.rs` — `total_size_bytes_is_present_for_revision_with_files`,
  `empty_revision_has_zero_total_size_bytes`. `cargo test -p lore-server --lib -- thinclient::v1::revision_`.
  The per-file field is verified with a real value; the aggregate asserts only `Some(0)`/`Some(_)` at
  the unit tier — see the tree-root aggregation gotcha below. Regenerating the proto bindings needs
  `protoc` on `PATH` (or `PROTOC=`); the crate otherwise builds off the committed `src/grpc/*.rs`.
- **CR-021 Part 1 (AWS SDK error-classification honesty, [SERVER])** —
  `lore-aws/src/aws_error.rs` owns the shared
  `is_retryable_sdk_error<E: ProvideErrorMetadata>(&SdkError<E, HttpResponse>) -> bool`, explicit
  `RETRYABLE_STATUS_CODES`, and `is_throttle_code`. Upstream 0.8.7's S3-authoritative redesign
  removed the old DynamoDB `metadata_load_error`; the shared classifier now feeds DynamoDB state
  reads plus the S3 `HeadObject`/`GetObject` mappers. The contract remains: retryable failures become
  `SlowDown`, modeled object absence alone becomes `AddressNotFound`, and permanent/non-SDK failures
  become source-preserving `Internal`. Coverage is `cargo test -p lore-aws --lib aws_error:: -j 4`
  plus `cargo test -p lore-aws --lib permanent_service_error -j 4`.
  - **`RETRYABLE_STATUS_CODES` is an explicit allow-list (`[429, 500, 502, 503, 504]`), not
    `status.is_server_error()`** — a permanent 5xx (501, 505) will never succeed on retry, and
    `push.rs`'s 10-attempt backoff means misclassifying one costs ~30-60s of pointless stalling
    before it's finally reported. Pair any "5xx is retryable" test with a sibling asserting a code
    **outside** the list (501 is the natural choice) is not — that's the actual regression this
    shape guards against. See `aws_error::tests::service_error_status_501_is_not_retryable`.
  - **`is_throttle_code` strips a leading Smithy shape-id namespace** before matching
    (`com.amazonaws.dynamodb#ThrottlingException` matches the same as bare `ThrottlingException`)
    — needed because this fork's deployment target (DigitalOcean Spaces, S3-compatible but
    non-AWS) may report the qualified form where AWS itself reports the bare name. Cover both
    spellings, not just AWS's bare one.
  - **`SdkError::ResponseError => true` is unconditional by design**, even at a 2xx status — a body
    truncated mid-transfer arrives with a successful status, and the SDK's own
    `TransientErrorClassifier` treats `is_response_error()` as transient regardless of status.
    Don't "fix" a test that asserts this at status 200; that's intended, not a bug.
  - **Real DynamoDB throttle responses arrive as HTTP 400** with the code identifying the exception
    (not HTTP 429) — pair a coded-error test with status `400u16` so it actually exercises the
    code-based classifier rather than accidentally passing via the 429/5xx status shortcut.
  - **Permanent S3 service errors need negative assertions as well as `is_internal()`.** A mapper
    test that only asserts `Internal` does not explicitly pin that the same error cannot be mistaken
    for missing or retryable after an error-enum refactor. For both `HeadObject` and `GetObject`,
    assert `is_internal() && !is_address_not_found() && !is_slow_down()`; the two
    `permanent_service_error` controls in `lore-aws/src/store/immutable_store.rs` are the pattern.
- **CR-021 Part 2a (SDK-level adaptive retry/backoff configuration, [SERVER])** —
  `lore-aws/src/clients.rs`. New `RetryMode` (`Standard` default / `Adaptive` opt-in /
  `Disabled`), `RetrySettings` (`mode`, `max_attempts`, `initial_backoff_millis`,
  `max_backoff_seconds`, all `#[serde(default)]`, now `PartialEq, Eq`), `impl
  From<&RetrySettings> for RetryConfig`, and `HttpClientSettings.retry: RetrySettings` (feeds
  `with_http_settings`'s `.retry_config(...)`) — closes the previous "no `retry_config` at
  all" gap (INV-AP: every client silently got the SDK's own 3-attempt standard retry). Part 2b
  (application-level backoff in `lore-revision`'s `state.rs`) is deliberately deferred — that
  crate also ships in the `lore` CLI, pending a client-risk decision; not covered here.
  Coverage: `cargo test -p lore-aws --lib -- clients::` (16 tests, all pure
  config-mapping/serde — no store/mock/network). Needed `toml`/`serde_json` as new `lore-aws`
  dev-dependencies (not previously present in this crate) to exercise the serde-defaulting
  cases; same `toml::from_str::<T>(s)` convention as `lore-server/src/plugins/aws.rs`'s
  existing config tests, just without the `toml::Value` + `.try_into()` indirection since
  `HttpClientSettings` already derives `Deserialize` directly.
  - **The shipped default is `RetryMode::Standard`, not `Adaptive`** — a first draft defaulted
    to adaptive, reversed in a reviewer pass after finding its rate limiter isn't bounded by
    `max_backoff` (worst case ~42s inside loreserver's flat 50s request-handler timeout; see
    the "AWS SDK adaptive retry's `ClientRateLimiter`..." Deep finding below). Pin this with a
    real equality assertion, not per-field checks, now that `RetrySettings` derives `PartialEq,
    Eq`: `retry_settings_default_is_standard_with_documented_defaults`,
    `http_client_settings_default_carries_retry_defaults`. `Adaptive` stays reachable and
    covered (`retry_mode_adaptive_maps_to_adaptive_retry_config`) — opt-in, not removed.
  - **Serde back-compat is the load-bearing case**: an existing deployed loreserver TOML
    config predates `[retry]` entirely. Three shapes must all land on the same
    `RetrySettings::default()` — key absent, whole document empty, and (a gap a reviewer pass
    flagged) `[retry]` present but empty:
    `http_client_settings_toml_with_no_retry_key_yields_standard_defaults`,
    `http_client_settings_empty_toml_yields_standard_defaults`,
    `http_client_settings_empty_retry_table_matches_absent_retry_key` (asserts the empty-table
    and absent-key results are `==` each other, not just each separately correct).
  - **`RetryMode::Disabled` maps through `RetryConfig::disabled()`, which silently ignores
    `RetrySettings`' `max_attempts`/backoff knobs** — see the dedicated Deep finding below;
    `retry_mode_disabled_maps_to_disabled_retry_config` pins the exact (surprising) resulting
    shape rather than assuming the configured overrides apply.
  - **Asserting the `max_attempts: 0 → 1` clamp's new `tracing::warn!`**: `#[traced_test]` +
    the macro-injected `logs_contain(...)` — `max_attempts_zero_clamp_is_logged` /
    `..._does_not_log_a_clamp_warning`. See the dedicated Deep finding below for the general
    pattern (first use of log-content assertions in this fork, vs. `#[traced_test]`'s prior
    use here only to keep logs out of other tests' output).
- **CR-016 (`RepositoryStorageStats`, per-repo stored-bytes accounting, [SERVER])** — new
  read-only RPC on `lore.repository.v1.RepositoryService`. `lore-storage/src/store_types.rs`'s
  `StoreRepositoryStats { fragment_count, payload_bytes, content_bytes }`;
  `ImmutableStore::repository_stats` is a **default** trait method returning
  `StoreError::NotSupported` (deliberate — the alternative is a hidden full-table scan on a
  backend with no repository-keyed access path, e.g. DynamoDB); only
  `lore-postgres::PostgresImmutableStore::repository_stats` overrides it. The current
  implementation joins distinct repository associations to `lore_fragment_state` and the
  non-authoritative `lore_fragment_metering` projection, backed by the
  `lore_fragments_repo_hash (repository, hash)` index (in both the inline `SCHEMA` const and
  `migrations/0001_init.sql`). Fragment representation metadata is authoritative on the S3
  object; stats repair missing projection rows from S3 and fail closed rather than returning an
  exact-looking undercount. `loreserver --rebuild-postgres-metering` rebuilds the full projection.
  `lore-server/src/grpc/repository/v1/repository_storage_stats.rs`'s `handler` re-checks repo
  authz via `check_repository_query_authorization` (CR-011's ReBAC callback) before any store
  call, then maps `StoreError::NotSupported → Unimplemented`, `SlowDown → ResourceExhausted`,
  anything else → `Internal`. Coverage:
  `cargo test -p lore-server --lib -- grpc::repository::v1::repository_storage_stats` (8 tests,
  reusing `authz_test_support::{new_test_stores, start_stub_auth_server}` from CR-011 — the deny
  case doesn't need `seed_repository_metadata` since this handler never reads metadata) — the
  authz-gate-runs-before-the-store deny case, own-repo-accepted (lands on `Unimplemented` since
  `LocalImmutableStore` has no override — comment explains why that, not `PermissionDenied`, is
  the pass signal), auth-OFF parity, missing-repository-id → `InvalidArgument`, and a **minimal
  in-test `ImmutableStore` stub** (`StatsStubStore`, every method but `repository_stats`
  `unimplemented!()`) proving the three response fields are copied through un-transposed plus the
  `SlowDown`/`NotSupported`/other-error → status-code mapping. `cargo test -p lore-storage --lib
  -- immutable_store::tests::repository_stats_default` (1 test) pins the trait default via a real
  `LocalImmutableStore` (cheaper and more honest than a hand-rolled fake, since a future backend
  adding its own accidental override wouldn't be caught by a fake). `cargo test -p lore-postgres
  --test immutable_store` (14 tests, was 10) adds 4 gated on `LORE_TEST_PG_URL` /
  `LORE_TEST_S3_ENDPOINT` / `LORE_TEST_S3_BUCKET`: unknown-repository → all-zero (not an error),
  a multi-fragment sum, same-hash-two-contexts-in-one-repo counted once (the
  `SELECT DISTINCT hash` assertion), and cross-repository isolation **plus** the intended
  full-double-count of a hash shared by two repositories (CR-016 requirement 3 — asserted as
  correct, not treated as a bug). Not run against live Postgres/MinIO here; compiles and skips
  cleanly per the established gate pattern (see the CR-007 entry above).
  **Gate note (same pattern as CR-015/WP-066):** `cargo +nightly fmt -p lore-postgres --
  --check` flags one diff in **implementation** code from this same delta —
  `lore-postgres/src/store/immutable_store.rs:887` (the `let _t = self.instruments.start(...)`
  line in `repository_stats` wraps differently under nightly rustfmt). Reported back, not
  reformatted (out of test-code scope); the sibling test files this pass touched
  (`lore-postgres/tests/immutable_store.rs`, `lore-storage/src/immutable_store.rs`,
  `lore-server/src/grpc/repository/v1/repository_storage_stats.rs`) are themselves fmt-clean.
  **`lore-proto`'s own hand-written proto-surface tests also needed updating**, since the new
  RPC is a 7th message pair on `lore.repository.v1`: `lore-proto/tests/v1_repository.rs`'s doc
  comment (6→7 RPCs) plus `RepositoryStorageStatsRequest`/`Response` added to both
  `v1_repository_request_response_types_default` and the field-shape destructuring net
  `v1_repository_field_shapes` (`{ id: _ }` / `{ fragment_count: _, payload_bytes: _,
  content_bytes: _ }` — this destructuring is exactly what catches a transposed/renamed field on
  a future regeneration, the same failure mode requirement 5's handler-level swap test above
  guards at the RPC layer). `lore-proto/tests/v1_lint.rs` needed no change (new messages carry
  `//` doc comments, use `id` not `repository_id`, reference no `urc.` types).
  **Unrelated pre-existing breakage found while running the crate-wide gate**: `cargo test -p
  lore-proto` failed to even compile due to `lore-proto/tests/v1_thin_client.rs` — a stale
  destructuring test from CR-008 (`TreeNode.size_bytes` / `Revision.total_size_bytes`, already
  landed and documented in the CR-008 entry above) that was never updated for those two fields.
  Confirmed via `git log` that file was last touched 2026-06-24, unrelated to CR-016 and to
  anything either this pass or a concurrent session changed. Fixed as a 2-field stale-test patch
  (same "test lagged the contract, ours to fix" disposition as any other stale destructuring net)
  since it blocked the exact `cargo test -p lore-proto` gate requested, and is unrelated to any
  implementation risk; flagged explicitly in the report back rather than folded in silently.
  Coverage: `cargo test -p lore-proto --test v1_repository --test v1_lint` (2 + 6 passed).
  **Live-infra run (the SQL/index gate), followed up on reviewer request:** stood up
  `postgres:16` (`-p 5433:5432`) + `minio/minio` (host ports `9090`/`9091` — this rig's
  `lorehub-dataplane` dev stack already owns `9000-9001`/`5432`, so the quickstart's literal
  ports collide; any free host ports work, the env vars just have to match), created the
  bucket with `aws --endpoint-url s3 mb` (aws-cli was on `PATH`; no `mc` binary needed), ran
  `cargo test -p lore-postgres --test immutable_store` for real — all 15 passed (11 pre-existing
  + 4 CR-016), not skip-green. **`EXPLAIN (ANALYZE, BUFFERS)` on the exact `repository_stats`
  query, after seeding 50k fragments across 500 synthetic repositories**, confirmed
  `Bitmap Index Scan on lore_fragments_repo_hash` for the association lookup and an indexed
  hash lookup for the then-current metadata join, with no sequential scan. The metadata table
  cited by that historical run has since been replaced by `lore_fragment_state` plus the
  rebuildable `lore_fragment_metering` projection; rerun `EXPLAIN` against those current tables
  when validating future query-plan changes. Tore both containers down after. Command for next
  time (adjust ports to whatever's free):
  ```
  docker run -d --name lore-pg-test -p 5433:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=lore postgres:16
  docker run -d --name lore-minio-test -p 9090:9000 -p 9091:9001 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data --console-address ":9001"
  ```
  **Two reviewer-named coverage gaps closed:**
  - **Projection-loss handling (supersedes the old inner-join exclusion behavior).** Current
    `repository_stats` uses completeness counts and repairs a missing
    `lore_fragment_metering` row from authoritative S3 object metadata. It fails the call if the
    object metadata or Stored lifecycle state is unavailable, so an association is never silently
    dropped from `fragment_count` or the byte sums. Coverage directly deletes the projection row,
    calls stats, and verifies exact repair. **Gotcha:** the workspace root
    `clippy.toml` (not `lore-server/clippy.toml`, which shadows it with only
    `future-size-threshold` and has no `disallowed-methods` list) forbids raw `tokio::spawn` —
    `lore-postgres` inherits the root list since it has no `clippy.toml` of its own, so driving
    the raw connection's I/O future needs `lore_base::lore_spawn!(async move { ... })` (the
    1-arg form, no `JoinSet` needed), not `tokio::spawn`. This is why
    `authz_test_support::start_stub_auth_server`'s bare `tokio::spawn` in `lore-server` passes
    clippy while the same pattern fails in a different crate — check which `clippy.toml` (if
    any) actually governs the crate you're in before assuming a sibling crate's pattern is safe
    to copy.
  - **Wrapper-store inheritance.** Neither `ReplicatedStore` (`lore-server/src/store/replicated_store.rs`)
    nor `GrpcReplica` (`lore-server/src/store/grpc_replica.rs`) overrides `repository_stats` —
    both forward every other op over their own wire protocol, which has no message for this one,
    so both silently inherit the trait default (`NotSupported`). This is the deployment-topology
    risk the reviewer flagged: a cell wired `composite`/`replicated` reports `Unimplemented` for
    metering even though the backend underneath could answer. Both got a one-line pinning test
    using each file's **already-established** mock fixture (not a new one): `GrpcReplica::new(MockReplicationClientImpl::default())`
    (`grpc_replica.rs`'s existing `mockall::automock`-generated mock, no `.expect_*()` needed
    since the default method never touches `self.client`) and the file's own `make_store()`
    helper for `ReplicatedStore<MockClient>` (`replicated_store.rs`, wrapped in
    `LORE_CONTEXT.scope(...)` like every other test in that file — `lore_spawn!`'s background
    refresh/monitor tasks need it). Neither construction was disproportionate; both files
    already pay this fixture cost for ~10-18 other tests. Coverage:
    `cargo test -p lore-server --lib -- store::grpc_replica::tests::repository_stats_inherits_the_trait_default`,
    `cargo test -p lore-server --lib -- store::replicated_store::tests::repository_stats::repository_stats_inherits_the_trait_default`.
  **Gotcha — stale incremental cache produced a bogus link error mid-session, unrelated to any
  code change.** After running `cargo clippy` then later `cargo build --tests`/`cargo test` as
  *separate* shell invocations (not chained in one `&&`) against the same `target/`, got `error:
  crate lore_revision required to be available in rlib format, but was not found in this form`
  (`lore-postgres`) immediately followed by a *different* spurious error on a clean retry:
  `error: cannot determine resolution for the macro lore_debug` / "import resolution is stuck"
  in `lore-server/src/quic/replication_store_service/client.rs` — a file nobody touched
  (confirmed via `git status`/`git diff --stat`, zero changes). Both cleared with a plain
  `cargo clean -p lore-server` (no full workspace clean needed) followed by a fresh build; this
  is a stale/corrupted incremental-compilation artifact, not a real error — don't spend time
  reading the named file when the error text doesn't match anything you actually edited there.
  If a `cargo build`/`test` error names a file with zero `git` diff, suspect the cache before
  the code.
- **CR-021 Part 2b (application-level `SlowDown` propagation honesty, ships in `lore-revision` —
  not cleanly [SERVER], flag as [CLIENT]-relevant)** — `lore-revision/src/state.rs`'s
  `collect_new_addresses` (the fn `collect_new_fragments` fans out into). Narrowed three
  pre-existing silent error swallows to propagate only overload (`StoreError::SlowDown` /
  `ImmutableError::SlowDown`) instead of every failure — the top-level per-fragment `query()`, a
  fragmented payload's own `load_raw` (`get()`), and the recursive `collect_new_addresses_recurse`
  over its children. Every non-`SlowDown` failure keeps the pre-existing conservative fallback
  unchanged (report-as-new, or drop-the-subtree) — deliberately, that residual gap is out of scope.
  `lore-server`'s `branch_push.rs::verify_fragments` also gained `.filter_slow_down()?`, mapping the
  propagated `SlowDown` to `Status::ResourceExhausted` instead of `internal`. Coverage:
  `cargo test -p lore-revision --test state` (42 tests — adds
  propagation-from-a-top-level-`query()` SlowDown, a non-SlowDown-preserves-conservative-fallback
  regression guard, a genuine-absence assumption pin against `find()`'s real `Ok(MatchNone)`
  behavior, the recursive-child-SlowDown case for a fragmented payload (swallow #3), a positive
  control that the fragmented walk yields real child addresses when unarmed, and swallow #2's
  actual outcome on the server path (see below));
  `cargo test -p lore-server --lib -- grpc::handlers::branch_push::tests` (adds
  `verify_fragments_maps_slow_down_to_resource_exhausted`, built via
  `RepositoryContext::new_server_context` + `crate::grpc::get_write_token()` — the base pattern is
  the "Real store fixture for a handler test" finding above; `get_write_token()` is the missing
  piece that finding doesn't cover, needed here because this test *mutates* state
  (`node_add`/`serialize`), not just seeds/reads one).
  - **Cheap fragmented-payload fixture, no big state needed.** `collect_new_fragments` only reaches
    a fragmented address via a real FILE node's content address (`collect_new_file_fragments` walks
    `to_node.address` for new/modified file nodes), not via the state's own structural blocks unless
    those happen to be large enough to fragment on their own. Hand-build instead of growing a state:
    store 2+ small raw chunks via `immutable::store_raw(repo, addr, fragment, bytes, true, false)`
    (`flags: PayloadStoredLocal`), build a `Vec<FragmentReference>` (`{ hash, offset_content }`,
    strictly increasing offsets) and store *that* as its own fragment with `PayloadStoredLocal |
    PayloadFragmented`, then `Node { flags: NodeFlags::File.bits(), address: <the list's address>,
    size: total_content_size, name_hash: hash_string(name), .. }` added to `state_to` only (so it's
    "new" relative to `state_from`). See `store_two_chunk_fragmented_payload` /
    `with_fragmented_file_fixture` in `lore-revision/tests/state.rs` — mirrors, and could eventually
    share code with, that same file's pre-existing `store_as_legacy_chunks` helper
    (`is_file_modified_chunking_compat` module). `store_two_chunk_fragmented_payload` now returns
    all three relevant addresses (`root_address, chunk_one_address, chunk_two_address,
    content_size`) so a test can arm a fault against either the fragmented root's own `get()` or
    either child's `query()` independently.
  - **Swallow #2 (own-fragment `get()` SlowDown) IS testable — the earlier "genuinely unreachable"
    call was solving the wrong problem.** A prior pass concluded no local-only fixture could observe
    *propagation* (see the "not reachable via a local-only test fixture" Deep finding, corrected
    below) and left it untested. True for propagation, but the actual question — does the SlowDown
    get **swallowed**, with the fragmented payload's children silently missing from the result —
    needs no remote/session mock at all: `FaultInjectingStore::arm_slow_down_get_for(root_address)`
    (new method, mirrors `arm_slow_down_query_for`) plus asserting on which addresses are **absent**
    from `collect_new_fragments`'s `Ok(_)` result, not on the `Err` path.
    `collect_new_fragments_swallows_slow_down_from_own_fragmented_payload_load` originally pinned
    the buggy `Ok` result with both children missing. CR-021 Part 2c keeps the test and flips it to
    require `Err` + `StateError::SlowDown` after `lore-storage::read::load_fragment` preserves a
    primary/local `StorageError::SlowDown` before remote fallback.
  - **CR-021 Part 2c read-layer controls ([CLIENT])** — `lore-storage/src/read.rs::tests` wraps a
    real `LocalImmutableStore` and injects `StoreError::SlowDown` or a generic deserialize-shaped
    failure from `get()`. Coverage:
    `cargo test -p lore-storage --lib -- read::tests::` and
    `cargo test -p lore-revision --test state
    tests::collect_new_fragments_swallows_slow_down_from_own_fragmented_payload_load -- --exact`.
    Symptom: expecting an offline pending `StorageSession` to expose `NoRemote` after a genuine
    local miss or generic local read failure makes both controls fail. Cause: the existing fallback
    normalizes those cases to `StorageError::AddressNotFound`. What to do: pin `SlowDown` only for
    the overload injection; pin `AddressNotFound` for genuine absence and generic deserialize
    failure, including the offline-session shape. Genuine Postgres not-found remains
    `AddressNotFound`; transient Postgres DB/pool/S3 `SlowDown` is now preserved by the same shared
    read boundary.
  - **Verdict on the lore-reviewer-vs-testing-guide disagreement (resolved 2026-07-26, executable
    check not a source read): the reviewer was right, this file's prior source-read note was
    correct too but incomplete — same underlying fact, viewed from "can I test propagation" instead
    of "what actually happens on this path."** On the server path (no remote session,
    `RepositoryContext` built the same way every fixture in this file builds one —
    `Err(ProtocolError::from(NoRemote))`, exactly what `RemoteState::Offline` collapses to per
    `repository.rs`'s `RemoteState::from_result`/`RepositoryContext::remote()`), a throttled local
    `get()` while loading a fragmented payload's own content does **not** propagate as `SlowDown` —
    it is silently swallowed and the subtree's addresses go missing from `collect_new_fragments`'s
    result, exactly as traced from `read.rs:272-298` / `state.rs:7663,7666`. Swallow #2's fix (the
    `Err(ImmutableError::SlowDown(traced))` arm at `state.rs:7663`) is real code but unreachable on
    this path — dead code for the server's own purpose (a push can be accepted without every
    referenced address actually confirmed durable). Swallow #3 (a *child* fragment's own `query()`,
    no `load_fragment`/remote-fallback layer in the way) is unaffected and does propagate correctly
    — see `collect_new_fragments_propagates_slow_down_from_fragmented_payload_child`.
- **2026-07-29 upstream-sync ITEM 2 integration evidence (docs-only, mixed classification).**
  Upstream commit `fe9a1c7` added `lore-integration-tests/src/revision_tree_test.rs`; this sync
  evidence entry records post-merge execution and adds no runtime delta. Related fork evidence
  remains classified as CR-008 **[SERVER]**, CR-021 Part 2b **[CLIENT]-relevant**, and CR-021
  Part 2c **[CLIENT]**.
  Symptom: the crate name suggests a live loreserver/cloud tier. Cause: this suite opens
  `LoreStorageOpenArgs { in_memory: 1, .. }` and drives the merged public revision-tree API directly.
  What to do: run `cargo test -p lore-integration-tests revision_tree_test -j 4`; it needs no
  loreserver, MinIO, DynamoDB, or Consul and passes 14/14 (0 failed/ignored, 113 filtered).
  `cargo test -p lore-integration-tests -j 4` passes 126, with one honest benchmark
  `#[ignore]` (`put_batch_api_within_overhead_budget_of_direct_write_content`) and 0 doc tests;
  the full suite also passed after Clippy. `cargo +nightly fmt --all` exits 0 with no diff, and
  `cargo clippy -p lore-integration-tests -j 4 -- -D warnings --no-deps` exits 0 with only benign
  Cargo build-script warnings about the missing installed Lore binary. Honesty audit: AWS/gRPC
  suites are compile-time feature-gated, Consul cases are explicit `#[ignore]`, and the only
  `return Ok(())` sites are idempotent bucket/table-exists setup, not silent infra skips. The
  14-test revision-tree suite covers batch fan-out, event ordering, multi-level and mixed-parent
  batches, concurrent batches, atomic rejection/error cases, entry-field round-trip including
  `size = 4096`, and a batch larger than one node block. The size assertion stops below CR-008's
  server proto/handler and aggregate-size paths, and the suite does **not** inject `SlowDown`;
  established CR-specific tests own those direct assertions.

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
- **`auth_api.proto`/`rebac_api.proto` compile with `.build_server(false)`** (`lore-proto/build.rs:178`)
  — `lore-server` is only ever a *client* of `UrcAuthApi` (`authnz/auth.rs`'s
  `LoreAuthClientHelper`), so there's no generated `UrcAuthApiServer` to bind a fake to for a test
  that needs the real ReBAC callback exercised end-to-end over the wire. Don't flip the build flag
  (out of test-code scope, and no CR asks for it); hand-roll a minimal stand-in mirroring the shape
  `tonic-prost-build` emits for a service that DOES have server codegen (compare
  `lore.repository.v1.rs`'s `repository_service_server`): `#[derive(Clone)] struct StubXService`
  implementing `tonic::server::NamedService` (`NAME` = the proto package+service, e.g.
  `"epic_urc.UrcAuthApi"`) and `tonic::codegen::Service<http::Request<B>>` (generic over `B: Body +
  Send`), dispatching on `req.uri().path()` to a per-RPC `tonic::server::UnaryService<Req>` impl via
  `tonic_prost::ProstCodec::default()` + `tonic::server::Grpc::new(codec).unary(...)`. `use
  tonic::codegen::*;` pulls in `BoxFuture`/`Body`/`StdError`/`Context`(task)/`Poll`/`http` the same
  way generated code does — don't hand-import those individually, it's fragile against tonic version
  bumps. Reusable implementation: `lore-server/src/grpc/handlers/repository_query.rs`'s
  `#[cfg(test)] pub(crate) mod authz_test_support::StubAuthService` (CR-011) — reuse it (it's
  `pub(crate)`) before re-deriving this for any other `UrcAuthApi` consumer.
- **Ephemeral-port test server: bind once, `serve_with_incoming`, no sleep.** Don't bind a
  `std::net::TcpListener`, read the port, drop it, and hand `Server::serve(addr)` a bare address to
  rebind — that drop-then-rebind window is a real TOCTOU race (another process can grab the port
  before the rebind), and it invites masking the remaining startup race with a fixed `sleep`, which
  is still flaky under load. Instead: `tokio::net::TcpListener::bind("127.0.0.1:0").await`, read
  `local_addr()` off it, then `.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
  listener))` on that same listener in a detached `tokio::spawn` — the socket is already in the OS
  listen backlog as soon as `bind` returns, before the spawned task's future is even first polled,
  so no readiness sleep is needed either. (CR-011's `authz_test_support::start_stub_auth_server`;
  caught in review after an initial bind-drop-rebind-plus-`sleep(100ms)` pass.)
- **Real store fixture for a handler test, without a full repo checkout.** Handlers taking raw
  `Arc<dyn lore_storage::ImmutableStore>` / `Arc<dyn lore_storage::MutableStore>` (most
  `lore-server/src/grpc/handlers/*.rs` signatures) don't need a full `RepositoryContext` to call —
  only to *seed* state before/after. `LocalImmutableStore::new(None,
  ImmutableStoreSettings::default())` → `Arc<LocalImmutableStore>` (coerces to `Arc<dyn
  ImmutableStore>`); `Arc::new(LocalMutableStore::new(None::<&Path>,
  MutableStoreSettings::default(), immutable.clone()))`; then
  `RepositoryContext::new_server_context(immutable, mutable, repository_id)` only where you need to
  seed/read directly (mirrors `handlers/path_diff.rs::tests::new_test_context`). To seed a
  repository's metadata pointer for `metadata_hash`/CAS tests: `repository::metadata_store(repo,
  RepositoryMetadata { .. })` (serializes into CAS, returns a `Hash`) then
  `repository::metadata_store_hash(repo, hash)` (publishes it as the mutable-store pointer).
  `RepositoryMetadata`'s `READ_ONLY_KEYS` (name/default-branch/default-branch-name/creator/created)
  must stay byte-identical between an `expected` and a proposed CAS blob or
  `RepositoryMetadataSet::validate_read_only_fields` rejects it before the CAS is even attempted —
  vary only `description` when building a "valid update" fixture for a CAS-success test. (CR-011's
  `authz_test_support::{new_test_stores, seed_repository_metadata}`.)
- **Tree-root size aggregate reads back `Some(0)` in handler unit tests even with sized files.**
  Symptom: a field sourced from `state.tree(repo).await?.size` (the root's rolled-up content sum, e.g.
  CR-008's `Revision.total_size_bytes`) is `Some(0)` though the test pushed File nodes with non-zero
  `node.size`. Cause: the rollup is only done by the real commit pipeline — `commit.rs`'s
  `rehash_directory_recurse` sums child `node.size` up each directory and `State::update_tree_root_hash`
  (`lore-revision/src/state.rs:1009`) moves the root's total into `Tree.size`. The flat handler-test
  fixture pattern (`State::new()` + raw `node_add(...)` + `serialize` + `branch_push::push`) never drives
  staging/commit, so nothing rolls up past the node you set. What to do: for a *per-node* size
  (`TreeNode.size_bytes` <- `TreePath.size` <- `node.size`) setting `size` on the `Node { .. }` literal
  before `node_add` is legitimate (see `push_branch_with_sized_files`). For an *aggregate* field, don't
  fake the rollup with low-level block writes or drive a full stage+commit in a handler unit test
  (disproportionate — a different tier); assert the plumbing invariant (`Some(_)` for a non-empty rev,
  `Some(0)` for an empty one where `hash_tree` stays zero and `state.tree()` returns `Tree::new_zeroed()`)
  and defer the real aggregate to the integration/e2e tier. The exact `Some(0)` was confirmed
  empirically (`eprintln!` + `-- --nocapture`), not assumed.
- **A `server.rs`-inline shutdown/signal composition that touches `DrainState` may only be
  pinnable from `drain.rs`'s own test module, not `server.rs`'s.** Symptom: want to prove
  "shutdown fires, then (if graceful_drain) blocks until `DrainState` is empty" for
  `launch_grpc_server`/`launch_http_server`'s inline shutdown future, using an "active
  connections > 0" case — but there's no public way to make `DrainState::total_active() > 0`
  without a real `quinn::Connection`. Cause: `QuinnConnectionRegistry`'s `count` field is
  private to the `drain` module; the existing drain tests simulate activity by poking it
  directly (`registry.count.store(n, Ordering::Relaxed)`, only legal because `drain::tests` is
  a *child* module of `drain` and inherits field access — see the "White-box state" finding
  above). `server::tests` is a sibling module, not a descendant, so it can't reach that field.
  What to do: write the mirror/composition test in `drain.rs::tests` instead (it already has
  the private-field access and everything `DrainState`-shaped needed), not in `server.rs`'s test
  module, even though the behavior under test conceptually "belongs" to `server.rs`. Don't add a
  `pub(crate)` test-only accessor on `ConnectionRegistry`/`DrainState` to unblock the other
  direction unless the delta's author signs off — that's an implementation change. See CR-009
  gRPC-leg follow-up above for the applied example (`drain::tests::shutdown_signal*`).
- **Pre-existing flake, not ours: `hooks::dispatch::tests::test_dispatch_pre_panic_isolation`.**
  Symptom: `cargo test -p lore-server --lib -- hooks` intermittently fails with "Expected
  Panic error" at `dispatch.rs:1187` (~1-in-3 on this rig); the same filtered run is
  green on another invocation with no code change. Cause: `std::panic::set_hook` is
  process-wide, and several `dispatch.rs` tests (`test_dispatch_pre_panic_isolation`,
  `test_dispatch_pre_panic_does_not_affect_other_hooks`, `test_spawn_post_panic_isolation`,
  `test_spawn_post_timeout_isolation`) install/restore it concurrently under the default
  multi-threaded test runner — same shared-global-state class of issue as the OTel
  `METER_PROVIDER` finding above, but in Epic's own `dispatch.rs` (`git log --oneline --
  lore-server/src/hooks/dispatch.rs` shows only the initial fork-copy commit — we've
  never touched this file). Confirmed unrelated to WP-066: reproduces identically with
  `lore-server/src/hooks/lorehub_notify.rs` fully `git stash`ed back to its last-committed
  state. Not ours to fix (not our delta, and it's implementation code besides). What to
  do: don't read a solo red `-- hooks` run as a WP-066 regression — re-run once, and
  scope the real gate to `-- hooks::lorehub_notify` (unaffected, always green) rather
  than treating the whole `hooks` module run as the pass/fail signal for a delta that
  doesn't touch `dispatch.rs`.
- **AWS SDK exception builders don't populate `.code()` unless `.meta()` is set explicitly.**
  Symptom: a service-error test built via `SomeException::builder().build()` doesn't exercise
  error-**code**-based classification even though the exception "is" that variant. Cause:
  smithy-codegen's builder defaults `meta: ErrorMetadata::default()` (code = `None`) — the real
  value is only populated when the SDK deserializes an actual wire response, not when a test
  constructs the exception directly. Fix: `SomeException::builder().meta(ErrorMetadata::builder()
  .code("ExceptionName").build()).build()`. Applies to any AWS SDK crate's modelled service error,
  not just DynamoDB — see `lore-aws/src/aws_error.rs::tests` (CR-021 Part 1 above) for worked
  examples.
- **AWS SDK adaptive retry's `ClientRateLimiter` is NOT bounded by `RetryConfig::max_backoff`.**
  Symptom: assuming `RetryConfig::adaptive()` + `.with_max_backoff(N)` caps total per-request
  delay at roughly `N`, and defaulting a server's retry mode to adaptive on that assumption —
  wrong, and the gap is large enough to blow through a flat request-handler timeout. Cause
  (verified in the vendored source — find the checkout path with `cargo metadata
  --format-version=1 | uv run -- python -c "import json,sys; d=json.load(sys.stdin);
  print([p['manifest_path'] for p in d['packages'] if p['name']=='aws-smithy-runtime'])"`, then
  read `<that dir>/src/client/retries/`): `strategy/standard.rs`'s
  `should_attempt_initial_request` returns `YesAfterDelay(delay)` straight from the token-bucket
  rate limiter, never clamped against `max_backoff`; `client_rate_limiter.rs`'s
  `INITIAL_REQUEST_COST = 1.0` over `MIN_FILL_RATE = 0.5` tokens/sec ⇒ up to ~2s stall before the
  *first* attempt when the bucket is drained, `RETRY_COST = 5.0` over the same fill rate ⇒ up to
  ~10s per retry. With `DEFAULT_RETRY_MAX_ATTEMPTS = 5` (`lore-aws`'s own default, CR-021 Part
  2a), worst case is roughly 42s — more than loreserver's flat 50s `request_handler_timeout`, and
  `max_backoff_seconds = 20` does nothing to prevent it. The limiter is also process-global per
  service client, so one tenant's throttling throttles every other tenant sharing that client.
  What to do: `lore-aws::clients::RetryMode` defaults to `Standard`, not `Adaptive`, because of
  this (the `Adaptive` variant's own doc comment carries this exact hazard so it doesn't get
  re-defaulted later); treat "adaptive implies `max_backoff` bounds worst-case latency" as false
  until re-verified against the vendored source for whatever SDK version is in use — at review
  time or in a test, not inferred from the `RetryConfig` builder API surface.
- **`aws_smithy_types::retry::RetryMode` has only `Standard`/`Adaptive` — `RetryConfig::disabled()`
  is not a third mode, it's `standard().with_max_attempts(1)`.** Symptom: a test that expects
  `RetryConfig::from(&settings).mode()` to reflect a caller's own "disabled" concept, or expects a
  caller's configured `max_attempts`/backoff to survive when retries are disabled, fails. Cause:
  upstream (`aws-smithy-types-1.4.8/src/retry.rs`) only defines `Standard`/`Adaptive`;
  `RetryConfig::disabled()` is literally `RetryConfig::standard().with_max_attempts(1)` — mode
  `Standard`, `max_attempts` forced to 1, `initial_backoff` 1s, `max_backoff` 20s (the SDK's own
  `standard()` builtins), regardless of what a caller's own settings say. `lore-aws`'s own
  `RetryMode::Disabled` (a different, crate-local enum) maps via an early `return
  RetryConfig::disabled()` in `impl From<&RetrySettings> for RetryConfig`
  (`lore-aws/src/clients.rs`) — which is why `RetrySettings`' `max_attempts`/backoff knobs are
  silently ignored under `mode = "disabled"`; intentional, not a bug
  (`retry_mode_disabled_maps_to_disabled_retry_config` pins the exact shape). What to do: read the
  vendored `RetryConfig`/`RetryMode` source before asserting on a "disabled" retry path in any
  AWS-SDK-based crate here — the useful getters are `.mode()`, `.max_attempts()`,
  `.initial_backoff()`, `.max_backoff()`, `.has_retry()` (`== max_attempts > 1`).
- **Asserting a `tracing::warn!`/`info!` fired, without hand-rolling a subscriber:
  `tracing_test::traced_test` + its macro-injected `logs_contain(&str)`.** `tracing-test` is
  already a workspace/`lore-aws` dev-dependency (used elsewhere, e.g.
  `lore-aws/src/store/immutable_store.rs`'s `#[traced_test]` tests and the OTel cases in
  `lore-aws/src/telemetry/aws.rs`), but before CR-021 Part 2a nothing in this fork actually
  asserted on captured log *content* — just used the attribute to keep logs from polluting other
  tests' output. Pattern: `#[traced_test]` above `#[test]` (that order for a plain test; async
  needs `#[tokio::test]` above `#[traced_test]`), then `assert!(logs_contain("substring"))` /
  `assert!(!logs_contain(...))` inside the test body — the function is injected by the macro into
  the test's local scope, not imported. It filters to log lines from the test's own span, so it
  stays isolated even under the default multi-threaded test runner. See
  `lore-aws/src/clients.rs::tests::max_attempts_zero_clamp_is_logged` /
  `..._does_not_log_a_clamp_warning`.
- **A CR spec naming a fork crate (e.g. `lore-postgres`) may not exist on the branch you're
  testing from, if that branch's lineage predates the crate's own merge into `tideshift/main`.**
  Hit during CR-021 Part 2a: its handoff named `lore-postgres` as an `HttpClientSettings`
  consumer to `cargo check`, but the CR branch was cut from upstream `main`, and `lore-postgres`
  (CR-007) lives only on `tideshift/main` — `cargo check -p lore-postgres` failed with "package ID
  specification did not match any packages" until the branch merged back into `tideshift/main`,
  where `cargo check -p lore-postgres` now passes as expected (confirmed post-merge, commit
  `7a2bd7b`). Not a bug in either CR; a branch-lineage fact, closed for this CR specifically. What
  to do: don't assume every crate a CR spec names exists on every branch — check the workspace
  `members` in the root `Cargo.toml`, or `git merge-base` against `tideshift/main`, before treating
  a missing `-p <crate>` as a real gate failure; skip it and flag the lineage gap in the report
  instead, then re-run once merged.
- **Three `ImmutableStore` fault-injection fixture patterns exist — pick the right one, don't
  invent a fourth.** By call shape, not by which crate they happen to live in:
  1. **Canned-response fake, no backing store** — `lore-revision/tests/composite_store.rs`'s
     `TestStore`/`DelayStore`. Every method returns a fixed value (optionally after a delay /
     after N calls, via an `AtomicU32` counter). Use when the code under test doesn't need to read
     back anything a *real* store would actually compute (a real Merkle/state-tree walk, real
     fragment flags) — cheapest to write, but can't back a `collect_new_fragments`-style test.
  2. **Unconditional-failure fake, no backing store** — `lore-server/src/lib.rs:54`'s
     `SlowDownImmutableStore`: every method returns `StoreError::from(SlowDown)`, no exceptions.
     Good for exactly one thing: proving a retry loop eventually exhausts and returns `SlowDown`
     (pair with `tokio::time::timeout(..)` — see the `STORE_RETRY_ATTEMPTS` finding below for why).
  3. **Wraps a real store, intercepts selectively** — `FaultInjectingStore`
     (`lore-revision/tests/state.rs`, CR-021 Part 2b) / `SlowDownQueryStore`
     (`lore-server/src/grpc/handlers/branch_push.rs`, same CR). Holds an `Arc<LocalImmutableStore>`
     and delegates every trait method straight to it (`self.inner.clone().<method>(..).await`)
     *except* `query()`/`get()`, which check an armable flag (a plain `AtomicBool`, or a
     `RwLock<BTreeSet<Address>>` for per-address targeting — `Address` derives `Ord` but not
     `std::hash::Hash`, so `BTreeSet` not `HashSet`) before either returning the fault or falling
     through to the same delegation. Use when the test needs `collect_new_fragments` (or anything
     else that walks a real Merkle/state tree) to behave normally right up until the one call you
     want to fail — build the fixture state fully against the store behaving normally, *then* arm
     the fault, *then* call the code under test. This is the only one of the three that composes
     with real `node_add`/`serialize`/`deserialize`.
- **A `SlowDown`-injecting test can silently take ~9 minutes unless backoff time is controlled.**
  Symptom: a test arms a store to return `StoreError::SlowDown` from `get()`/`query()`, asserts
  correctly, but the single test dominates the whole suite's wall time (400-550s, near-identical
  across separate runs — no meaningful jitter). Cause: `lore_storage::read::read_raw`
  (`lore-storage/src/read.rs:34`) retries a `SlowDown` internally — default policy is 60 attempts,
  50ms→10s exponential backoff, uncapped total wall time (~530s worst case, matching what's
  observed almost to the second, since the schedule has no jitter). This is the deliberately
  *patient* client policy, sized for a CLI talking to a real overloaded server — not what a
  fault-injection unit test wants. In a unit-test binary that has other storage reads, do **not**
  try to win the global retry-count race from inside the test:
  ```rust
  #[tokio::test(start_paused = true)]
  async fn persistent_slow_down_is_fast() { /* ... */ }
  ```
  Enable Tokio's `test-util` feature under the crate's `[dev-dependencies]`. Paused time lets the
  full production retry schedule advance virtually and is deterministic under the parallel
  harness. Proven by CR-021 Part 2c: `cargo test -p lore-storage` fell from 538.74s (both new tests
  reported running over 60s) to 2.18s of test time. `STORE_RETRY_ATTEMPTS` is a process-wide,
  first-writer-wins `OnceLock<usize>` (`lore-storage/src/lib.rs:211`); an in-test `.set(1)` can lose
  to any other parallel test that initializes the default first. `lore-server/src/lib.rs`'s
  `#[ctor::ctor] fn init_test_policies()` already calls the equivalent
  `lore_storage::assume_server_policies()` (sets it to 7) for the *whole* `lore-server` test binary;
  that crate-level pre-harness bootstrap remains safe. Applies to any future persistent-overload
  fault-injection test, not just CR-021.
- **`collect_new_addresses`'s "own fragment `get()` SlowDown" swallow is not reachable via a
  local-only test fixture — real in production, but only under a specific topology.** Tried (CR-021
  Part 2b) to test that a `SlowDown` from `get()` while loading a fragmented payload's own content
  (to read its child `FragmentReference` list) propagates as `StateError::SlowDown` rather than
  silently dropping every child. Building the fragmented fixture worked fine (see the CR-021 Part 2b
  entry above), but the propagation itself could not be observed. Cause:
  `lore_storage::read::load_fragment` (`lore-storage/src/read.rs:211`, called via
  `lore_revision::immutable::load_raw`) discards the *specific* local error type on any local-read
  failure (maps it to an internal `LocalFailure::Other`, losing whether it was `SlowDown` vs.
  anything else), then — because `ReadOptions::default().remote == true` and `load_raw` always
  passes `Some(session)` — unconditionally attempts a remote fetch as the tie-breaker. In a test
  repository built with `Err(ProtocolError::from(NoRemote))` (the standard fixture pattern in this
  file), that remote attempt fails with a `NoRemote`-shaped error, which *becomes* `load_raw`'s
  final `Err`. `SlowDown` never survives to reach `collect_new_addresses`'s
  `Err(ImmutableError::SlowDown(_))` match arm — it falls into the pre-existing, deliberately
  unchanged `Err(_) => {}` branch instead, and the fragment gets added via the normal
  not-durably-stored path, so the test's `collect_new_fragments` call returns `Ok` where it should
  have returned `Err`. Net effect: **in production this propagation branch is real and reachable**,
  but only when the *effective* answer from `load_raw` (local-with-remote-fallback) is itself
  `SlowDown` — i.e. a working remote session is present and *it* returns `SlowDown` (the
  durable/replica tier is what's overloaded), not simply when a purely local read hits `SlowDown`
  with no remote configured. What to do: don't re-attempt this with a bigger/different local-only
  fixture — it structurally cannot reach the branch, no matter how the local store is built. Testing
  it properly needs a mock `StorageSession`/transport that returns `ProtocolError::SlowDown`, which
  is a materially heavier lift (out of proportion for a unit-style fixture) than the pattern above;
  flag it as a known gap rather than rebuilding this investigation. The sibling swallow (a *child*
  fragment's own `query()`, called directly by `collect_new_addresses` with no
  `load_fragment`/remote-fallback layer in between) has no such obstruction and is fully covered —
  see `collect_new_fragments_propagates_slow_down_from_fragmented_payload_child` in
  `lore-revision/tests/state.rs`.
  - **Correction (2026-07-26): the "known gap, flag it" disposition above was too pessimistic —
    the *propagation* path is genuinely untestable locally (as analyzed), but that's not the
    question that matters for integrity.** The question that matters is whether the SlowDown gets
    **swallowed** with children going missing from the result, and that half needs nothing more than
    the local-only fixture already built here: arm `get()` to fail with `SlowDown` on the fragmented
    root's own address (`FaultInjectingStore::arm_slow_down_get_for`, new method) and assert the
    child addresses are **absent** from `collect_new_fragments`'s `Ok(_)` result instead of asserting
    on `Err`. See `collect_new_fragments_swallows_slow_down_from_own_fragmented_payload_load` — this
    is the discriminating test that settled the lore-reviewer disagreement in the CR-021 Part 2b
    entry above (reviewer was right: swallow #2 is dead code on the server/no-remote-session path).
    Lesson for next time: when a propagation path is unreachable in a fixture, don't stop at "can't
    test the fix" — check whether the *swallow* (the thing the fix was meant to prevent) is
    independently observable via the `Ok` result's contents. It usually is; that's the assertion
    that actually matters to a reader anyway (see this file's own CR-021 Part 2b write-up: "the
    assertion that matters is not 'an error came back' but whether addresses go missing").
