# Configurable AWS client retry (CR-021 Part 2a)

**Date:** 2026-07-25
**Status:** Done (fork-side, merged locally into `tideshift/main`; not pushed or submitted upstream)
**Classification:** [SERVER]

## Summary

CR-021 Part 2 asked for "adaptive retry + backoff on the per-fragment path" and offered two
routes to get there. This chunk lands only the SDK-config half — calling it **2a**. INV-AP found
that every AWS client in `lore-aws` was built from `aws_config::defaults(...)` with no
`retry_config` at all, so each one silently ran on the SDK's own default (3 attempts, 1s base
backoff) with no way for a deployment to override it. Added a configurable `RetrySettings`
instead. The other route (2b — `state.rs:7561`'s `if let Ok(query)` swallowing a throttle into
"no result") is deferred: it lives in `lore-revision`, which also ships in the `lore` CLI, so it
needs a client-risk decision first (see `lore-fork-patches-inventory` on labelling changes
[SERVER] vs [CLIENT]).

## What changed

- `lore-aws/src/clients.rs`: new `RetryMode` enum (`Standard` / `Adaptive` / `Disabled`) and
  `RetrySettings` (`mode`, `max_attempts`, `initial_backoff_millis`, `max_backoff_seconds`),
  nested under the existing `[.*.http]` config as `#[serde(default)]` — every existing deployed
  loreserver config loads unchanged. Defaults: **standard** mode, 5 attempts, 100ms base, 20s
  ceiling. `max_attempts` clamps to at least 1 and logs when it does, so a malformed value can't
  silently mean "never send the request".
- `lore-aws/Cargo.toml`, `Cargo.lock`: no new dependency, just the `RetryConfig` builder surface
  already available from the existing `aws-config`/`aws-smithy-types` deps.

## The default-mode reversal (worth recording as narrative)

I originally defaulted to `adaptive` — ADR-00022 step 0 and the CR text both say "adaptive", and
that's what I shipped first. `lore-reviewer` challenged it, and I verified the hazard directly in
the vendored SDK source:

- `aws-smithy-runtime-1.11.3/src/client/retries/strategy/standard.rs` —
  `should_attempt_initial_request` returns `YesAfterDelay(delay)` straight from the rate limiter,
  **not clamped by `max_backoff`**.
- `client_rate_limiter.rs:30,34` — `INITIAL_REQUEST_COST 1.0 / MIN_FILL_RATE 0.5` = up to 2s
  before the *first* attempt; `RETRY_COST 5.0 / MIN_FILL_RATE 0.5` = up to 10s per retry.

At 5 attempts that's roughly 42s of sleeping inside loreserver's flat 50s
`request_handler_timeout` — defaulting to adaptive would have converted throttling into handler
timeouts. The limiter is also process-global per service, so one tenant's throttling would delay
every other tenant sharing that client.

Flipped the default to `standard`; `adaptive` stays available and opt-in, with the hazard
documented on the enum variant itself. Standard + 5 attempts + 100ms is still strictly better than
before (5 attempts vs 3; ~1.5s worst-case backoff vs ~3s), so the upstream story is "make retry
configurable", not "change everyone's retry behavior".

**Consequence:** we do not get adaptive retry for free on Spaces. Enabling it is a
deployment-config decision, and INV-AP's advice to raise `request_handler_timeout_seconds` above
50 becomes a *prerequisite* for turning it on, not a nice-to-have.

**Operator-facing note:** supplying an explicit `RetryConfig` replaces the SDK's
environment-driven retry provider rather than merging with it — `AWS_RETRY_MODE`,
`AWS_MAX_ATTEMPTS`, and the equivalent profile keys no longer take effect once `RetrySettings` is
in play.

## Interaction with Part 1 / the deferred 2b

Part 1 (worklog 007) made `load_metadata`/`query` honest about throttling instead of reporting it
as missing content. 2a partially mitigates the still-unfixed 2b: the SDK now retries throttles
*below* the `state.rs` swallow, so far fewer throttled queries reach `if let Ok(query)` at all. It
doesn't fix it — a persistent throttle that exhausts all 5 attempts still gets silently turned
into "no result" — but it narrows the window considerably.

## Why now

Traced by `../lorehub/docs/investigations/inv-ap-large-push-dynamo-fanout-timeout.md`; sequenced
by `../lorehub/docs/adr-00022-caching-strategy-and-sequencing.md`. Spec:
`../lorehub/docs/lore-change-requests/cr-021-throttle-honesty-and-fragment-fanout-backoff.md`
(Part 2a only; 2b and Part 3 not started).

## Tests and gates

`lore-test-specialist` owned the tests: 16 tests in `clients::tests` covering mode mapping
(including `Disabled`'s surprising shape — `RetryConfig::standard().with_max_attempts(1)`, not a
literal "off"), the `max_attempts: 0` clamp and its new warning, backoff `Duration` conversion,
and serde back-compat for absent / empty / partial `[retry]` tables in both TOML and JSON.

Final on merged `tideshift/main`: `cargo test -p lore-aws` — **123 passed / 0 failed / 2 ignored**
(pre-existing). `cargo +nightly fmt --all` clean. `cargo clippy -p lore-aws --all-targets --
-D warnings --no-deps` clean. `cargo check -p lore-postgres -p lore-server` clean — that check
mattered because `lore-postgres` constructs `HttpClientSettings` and exists **only** on
`tideshift/main`, so it couldn't be verified on the CR branch itself.

## Reviewer findings (`lore-reviewer`)

Applied: the `adaptive`-by-default choice, corrected to `standard`-by-default per the narrative
above (this was the substantive finding of the pass).

## Follow-ups

- CR-021 Part 2b (`state.rs:7561` swallowing an exhausted-retry throttle into "no result") remains
  open — needs a [CLIENT] risk decision first, since `lore-revision` ships in the `lore` CLI.
- CR-021 Part 3 (batching the tree-walk) remains open, tracked in the CR spec.
- Enabling `adaptive` mode on any real deployment is gated on first raising
  `request_handler_timeout_seconds` past 50s — not tracked as a separate item yet.
