# Bounded retry on the lorehub_notify post-commit hook (WP-066 Chunk 2)

**Date:** 2026-07-08
**Status:** Done
**Classification:** [SERVER]

## Summary

Chunk 1 (WP-066 Part 1, `7a6a57f`) added OTel delivery-outcome counters to the
`lorehub_notify` post-commit hook but left every POST single-shot. Chunk 2 adds bounded
in-process retry (option C) so a transient failure — network blip, timeout, or a 5xx/429 from
the receiver — doesn't silently drop a notification. Non-retryable 4xx still fails fast; a 2xx
still succeeds on the first attempt. No persistent outbox; delivery is now at-least-once
within a bounded window, not durable across process restarts (that remains option A, the
escalation if this proves insufficient).

## What changed

- `lore-server/src/hooks/lorehub_notify.rs` — the bulk of the diff:
  - Retry loop using `lore_revision::util::time::RetryPolicy` (bounded backoff), classifying
    outcomes into retryable (transport error/timeout, HTTP 5xx, HTTP 429) vs terminal (2xx,
    any other 4xx).
  - Default policy: 2 retries, 200ms → 2s backoff. Optional
    `[hooks.lorehub_notify.retry]` config table (new `RetrySettings`) to override.
  - Per-attempt timeout lowered 10s → 5s, and `timeout=0` now rejected at config-parse time —
    both so worst case (attempts × timeout + backoff) stays under the dispatcher's 30s
    post-handler cap.
  - Body is signed once and cloned per attempt (not re-signed), so a retried POST carries the
    identical signature + `event_id` as the original — the receiver's `event_id` idempotency
    check dedups it if an earlier attempt actually landed before the caller saw a failure.
  - New `retries` OTel counter alongside the existing `deliveries` counter (which still records
    only the terminal outcome).
- `docs/testing-guide.md` — recorded the new hooks::lorehub_notify test coverage + the
  transport-flake gotcha (see Notes below).
- `docs/worklogs/README.md` — this entry's index row.

## Why now

WP-066 is the notify-hook hardening arc; Chunk 1 gave us visibility (counters) but no
resilience. Chunk 2 closes the gap for the common transient-failure case before deciding
whether the durability escalation (option A, persistent outbox) is actually warranted.

## Tests

24 `lore-server::hooks::lorehub_notify` tests green (+8 over Chunk 1's baseline), covering
retry-vs-fail-fast classification, backoff bounds, `timeout=0` rejection, and idempotent
event_id reuse across attempts. `cargo clippy --all-targets -- -D warnings --no-deps` and
`cargo +nightly fmt --all` both clean.

## Reviewer findings (lore-reviewer)

Classified [SERVER], no blocking issues.

- **Applied:** reject `timeout=0` at config-parse time (a silent-no-timeout footgun).
- **Deferred:** a config-time budget guard that fails loudly if an operator's
  `timeout × (attempts + 1) + backoff` exceeds the dispatcher's 30s cap — currently doc-protected
  only, not enforced.
- **Skipped:** a unit test simulating transient-transport-recovery specifically, judged
  flake-prone; the 503/429-recovery and persistent-transport-failure tests already cover the
  retry path without depending on a real transport-level flake.

## Notes / surprises

- Unrelated to this change: `hooks::dispatch::tests` has a pre-existing intermittent flake
  (a panic-hook race in Epic's own dispatch harness, not ours). Scope any green-gate run to
  `-- hooks::lorehub_notify` rather than the whole `hooks` module.
