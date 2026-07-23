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
- **CR-008 (per-entry byte size on tree reads, [SERVER])** — additive proto3 optional
  `TreeNode.size_bytes` (FILE only, unset for DIRECTORY/LINK) + `Revision.total_size_bytes` on
  `lore.thin_client.v1`; `lore-revision/src/state.rs` `TreePath.size` (<- `node.size`, populated in
  `gather_tree_paths_node`); handlers `thinclient/v1/revision_tree.rs` (File-gates the field) and
  `revision_info.rs` (`total_size_bytes` <- `state.tree(repo).await?.size`, non-fatal → `None` on
  error). Tests in the existing `#[cfg(test)] mod test` blocks:
  `revision_tree.rs` — `file_size_bytes_reflects_node_content_size` (asserts `Some(123)` + a 0-byte
  file `Some(0)`, distinct from unknown `None`), `directory_size_bytes_is_unset`,
  `link_size_bytes_is_unset` (new fixture `push_branch_with_sized_files`, sets `node.size` directly);
  `revision_info.rs` — `total_size_bytes_is_present_for_revision_with_files`,
  `empty_revision_has_zero_total_size_bytes`. `cargo test -p lore-server --lib -- thinclient::v1::revision_`.
  The per-file field is verified with a real value; the aggregate asserts only `Some(0)`/`Some(_)` at
  the unit tier — see the tree-root aggregation gotcha below. Regenerating the proto bindings needs
  `protoc` on `PATH` (or `PROTOC=`); the crate otherwise builds off the committed `src/grpc/*.rs`.

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
