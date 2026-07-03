# 001 — Opt-in graceful QUIC drain for loreserver (CR-009)

**Date:** 2026-07-03
**Status:** Done

## Summary

**[SERVER]** loreserver's QUIC shutdown was an immediate force-close with no in-flight tracking —
flagged by the Lorehub zero-downtime-deploy plan's shutdown-path inventory (INV-AF, in the
`lorehub` repo), and confirmed against industry drain/handoff patterns as the gap to close before
rolling deploys are safe (DO load balancers do no draining of their own). CR-009 adds an opt-in
graceful drain: on SIGTERM/SIGINT, QUIC accept loops refuse new connections while established
connections run to completion, with a stall guard so an idle/wedged peer can't block an unbounded
drain indefinitely. Default-off — absent config preserves the historic close-after-timeout
behavior exactly.

## What changed

All in `lore-server` (commit `958c307` on `cr-009-graceful-drain`, merged to `tideshift/main` as
`35d50f9`):

- **`src/drain.rs` (new)** — `DrainConnection` trait (mockable), `ConnectionRegistry` (established
  + pending-handshake counts via RAII guards), `DrainState` aggregate, `run_drain` loop (unbounded
  by default; stall guard keyed on stream-frame progress so keep-alive PINGs don't mask an idle
  peer; closes a stalled connection at most once per window), OTel gauges.
- **`quic/quinn/`** — accept loops call `Incoming::refuse` while draining; the handshake guard is
  taken synchronously pre-spawn to close the mid-handshake race (a connection can't be cut by the
  close that follows drain completion); `handle_conn` registers established connections.
- **`server.rs` / `settings.rs`** — new `[server]` keys `graceful_drain` /
  `drain_timeout_seconds` (0 = unbounded) / `drain_stall_timeout_seconds` (default 300; startup
  warning fires when both timeouts are 0, i.e. no backstop at all). `wait_for_shutdown` changed
  `Duration` → `Option<Duration>`. HTTP server stays up through the drain.
- **HTTP** — `/health_check` returns 503 while draining (LB eviction signal); new unauthenticated
  `/drain_status` JSON route for deploy controllers. This route replaced the CR's originally
  proposed gRPC admin RPC deliberately: tonic GOAWAYs new connections at signal, so a gRPC-based
  status poll would itself be unreachable mid-drain.
- `docs/testing-guide.md` gained a CR-009 section (crate/test map) plus a new deep-findings entry
  on deterministic `start_paused` tokio-timer tests for the drain loop.

## Why now

Directly unblocks the Lorehub zero-downtime-deploy work package: rolling deploys need loreserver
to survive a SIGTERM without severing in-flight QUIC transfers.

## Reviewer findings

`lore-reviewer` — no blockers. Applied: pending-handshake counter (closes the mid-handshake race),
single-close-per-stall-window (avoids repeatedly hammering an already-closing connection), 0/0
startup warning (silent unbounded-with-no-backstop was a footgun). Declined: a params-struct
refactor for the settings, and treating the always-on connection registry as a cost worth gating
(deliberate — it's the observability surface `/drain_status` reads).

## Verification

25 new deterministic tests (`#[tokio::test(start_paused = true)]` — paused-clock drain loop,
settings parsing/defaults, health/status handlers, bounded vs unbounded shutdown). Full
`lore-server` suite green: 777 on the CR branch, 818 on merged `tideshift/main`. `cargo +nightly
fmt --all` / `cargo clippy --all-targets -- -D warnings --no-deps` clean.

## Follow-ups created

- Live QUIC drain against a real endpoint is manual/e2e only — no accept-loop mock seam exists for
  it; not covered by the automated suite.
- Upstream PR to `EpicGames/lore` deferred to the user's say-so (this CR is on `tideshift/main`,
  not yet split to a per-CR upstream branch).

## Notes / surprises

Merge of `cr-009-graceful-drain` into `tideshift/main` hit an add/add conflict on
`docs/testing-guide.md` (both branches had appended sections); resolved by folding the CR branch's
testing knowledge into the already-established `tideshift/main` guide rather than picking a side.
