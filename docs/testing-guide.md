# Lore fork testing guide

Fork-specific testing knowledge for `tideshift/main` deltas. This file is a **local fork
addition** (excluded from per-CR branches sent upstream) — see `lore/CLAUDE.md`. Owned by the
`lore-test-specialist` agent: read it first, upsert it at the end of every run.

## Build/test scope

- **Always scope to the crate you touched**: `cargo test -p <crate>`, not a bare `cargo test`
  (workspace-wide test builds add tens of GB to `target/`, already ~60GB+ on this rig — see
  `lore/CLAUDE.md` "Local-test gotchas").
- Filter to a module path with `cargo test -p <crate> --lib <module>::` — note cargo only accepts
  **one** filter argument; run separate invocations per module rather than a space-joined list.
- `cargo clippy -p <crate> --tests --no-deps -- -D warnings` scoped the same way is fast (~30s
  incremental) once the lib itself has compiled once; use it as a pre-report gate on test code
  without triggering a full-crate clippy pass that might also flag main-session in-progress
  non-test code.

## Testing tokio time-based logic deterministically (CR-009 drain machinery)

`lore-server`'s `drain` module (`lore-server/src/drain.rs`) runs on real `tokio::time::interval`
ticks (1s drain loop, 250ms wait_idle poll) — too slow to assert against with real sleeps across
dozens of test cases. Fix: **`#[tokio::test(start_paused = true)]`** + `tokio::time::timeout(...)`
around the awaited future. Under a paused clock, tokio auto-advances virtual time to the next
timer once every task in the runtime is blocked on one — no manual `tokio::time::advance()` calls
needed. Pattern used throughout `drain::tests`:

```rust
#[tokio::test(start_paused = true)]
async fn some_test() {
    let handle = tokio::spawn(async move { run_drain(&registry, None, None).await });
    tokio::time::sleep(Duration::from_secs(5)).await;   // auto-advances instantly
    assert!(!handle.is_finished());
    drop(guard);
    tokio::time::timeout(Duration::from_secs(5), handle).await.unwrap().unwrap();
}
```

**Gotcha:** `start_paused = true` needs the `test-util` tokio feature, which the workspace-wide
`tokio` dependency does **not** enable by default (`lore/Cargo.toml:130-141` only turns on
`fs, io-util, macros, net, parking_lot, rt, rt-multi-thread, signal, sync, time`). Add it as a
crate-local dev-dependency override, not a workspace-wide change (no other crate needed it as of
2026-07-03):

```toml
# <crate>/Cargo.toml
[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
```

Symptom without it: `error[E0599]: no method named 'start_paused' found for struct
tokio::runtime::Builder` (a confusing error — it's not actually about `Builder`, it's the macro
expansion failing because the feature-gated method doesn't exist).

## Testing a private `#[cfg(test)] mod` nested in the same file (white-box access)

`ConnectionRegistry<C>`/`DrainState` keep their counters (`count: AtomicU64`,
`registries: Mutex<Vec<...>>`) private. A `#[cfg(test)] mod tests` declared **inside the same
file** is a child module and gets ordinary Rust field-privacy access to its parent's private
fields — use this to simulate states that are otherwise impossible to construct in a unit test
(e.g. a `ConnectionRegistry<quinn::Connection>` with N "active" connections, since a real
`quinn::Connection` only comes from a live QUIC handshake). See `drain::tests::
drain_state_aggregates_active_counts_across_registries` and `wait_idle_resolves_once_active_
count_returns_to_zero`, which poke `registry.count.store(n, Ordering::Relaxed)` directly. This
only works from a **child** module of the type's defining module — a sibling module (e.g.
`http::drain_status::tests`) cannot reach into `drain::ConnectionRegistry`'s private fields and
must go through the public API instead (in `drain_status::tests` this means registries always
report `active: 0` — acceptable, since the test is about JSON shape, not counts).

## `DrainConnection` trait — mock pattern for connection-registry logic

`drain.rs`'s `DrainConnection` trait exists specifically so the registry/drain-loop logic is
testable without a live QUIC endpoint (`quinn::Connection` is the only production impl and can't
be constructed by hand). Test double used throughout `drain::tests::MockConn`: wraps
`Arc<AtomicU64>` (frame count) + `Arc<AtomicBool>` (closed flag) so a `.clone()` kept by the test
observes the same state as the clone the registry holds internally (registries store connections
by value, so without shared interior state a clone-out via `snapshot()` would be unobservable from
outside). `drain_close()` just flags `closed`; it does **not** remove the connection from the
registry — that mirrors production (`run_drain` only calls `.close()`, the connection *handler*
task is what eventually drops the `ConnectionGuard`), so a test asserting stall-guard behavior
must hold the guard for the test's duration and assert the flag, not `registry.active() == 0`.

## `DrainState` is concretely typed to `QuinnConnectionRegistry`, not generic

`DrainState::add_registry` takes `Arc<QuinnConnectionRegistry>` (`= Arc<ConnectionRegistry<quinn::
Connection>>`), not a generic `Arc<ConnectionRegistry<C>>`. This is a design choice (DrainState
only ever aggregates real QUIC endpoints in production) but it means DrainState-level tests can't
inject `MockConn` — only `ConnectionRegistry<C>`/`run_drain` (generic over `C: DrainConnection`)
can. Worth knowing before reaching for a mock at the `DrainState` layer; use the private-field
poke trick above instead.

## `lore-server` HTTP handler tests — `axum_test::TestServer` pattern

Established in `lore-server/src/http/health_check.rs`, reused for `drain_status.rs`: build a
minimal single-route `axum::Router` with `.route("/path", routing::get(handler).with_state(...))`
for handler-only unit tests, or go through `crate::http::server::create_router(...)` (needs a real
`ServerState` via `crate::store::test_store_create()`) when the thing under test is route
**placement** (e.g. proving `/drain_status` sits in the unauthenticated merge, not the `/v1`
authenticated nest) rather than just handler logic. For JSON body assertions, deserialize into
`serde_json::Value` rather than adding `Deserialize` to a production response struct that only
needs `Serialize` in non-test code (`DrainStatusResponse`/`DrainEndpointStatus` in
`http/drain_status.rs`) — keeps the test-only need out of prod code.

## CR-009 — graceful QUIC drain ([SERVER], `lore-server`)

Delta lives entirely in `lore-server`: new `src/drain.rs` module (`DrainConnection` trait,
`ConnectionRegistry<C>`, `DrainState`, `run_drain`), `ServerSettings.{graceful_drain,
drain_timeout_seconds, drain_stall_timeout_seconds}` in `settings.rs` (all `#[serde(default)]`,
default-off), `wait_for_shutdown` in `server.rs` changed from `Duration` to `Option<Duration>`
(`None` = unbounded), and `ServerHealth.drain: Option<Arc<DrainState>>` gating a 503 in
`/health_check` plus the new unauthenticated `/drain_status` JSON route. Full test coverage:
`cargo test -p lore-server --lib drain::` (registry mechanics, `run_drain` timing/stall-guard),
`--lib server::tests::wait_for_shutdown_tests` (bounded force-abort unchanged, new unbounded mode
actually waits), `--lib settings::tests` (new keys parse + default), `--lib health_check::` /
`--lib drain_status::` (503-on-drain, JSON shape, route placement). All green, real QUIC endpoint
behavior (accept-loop refusal in `quic/quinn/quinn_server.rs`) intentionally left to manual/e2e —
no mock-friendly seam there and out of scope per the CR.
