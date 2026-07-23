# Provider-neutral authentication refresh (CR-020)

**Date:** 2026-07-23
**Status:** Done (fork-side, merged locally; not pushed or submitted upstream)
**Classification:** [CLIENT]

## Summary

CR-020 completes Lore's provider-neutral authentication lifecycle so a capable provider can
bootstrap and renew a short-lived authentication JWT without another interactive login. Lore
stores and presents an opaque refresh credential, refreshes five minutes before expiry, and keeps
a still-valid caller token across bounded provider or coordination failures. Provider policy and
the remaining Commit0 server work stay outside this fork delta.

## What changed

- `lore-proto/proto/auth_api.proto` and generated `lore-proto/src/grpc/epic_urc.rs`: added
  wire-compatible optional `UserToken.refresh_token` field 5.
- `lore-transport/src/auth/ucs_auth.rs`: shared poll, external-exchange, and refresh response
  mapping; `RefreshAuthSession` keeps its empty request and sends the opaque credential as
  sensitive bearer metadata.
- `lore-transport/src/auth/exchange.rs`, `traits.rs`, and `types.rs`: added the five-minute
  refresh lead and shared repository/custom-resource orchestration, with bounded provider and
  lease timeouts, fallback to a still-valid caller token, and recipient/identity checks after
  coordination.
- `lore-credential/src/token_store.rs`: added a crash-released per-`(auth_url, identity)` OS-file
  lease, post-acquisition reload, cross-process AES-GCM nonce reservation, and guarded atomic
  authn/refresh pair replacement.
- `lore-revision/src/auth/login.rs`: interactive and external login now store the initial authn
  token and optional refresh credential as one pair.
- Pair writes publish to the in-process cache only after persistence succeeds. Missing replacement
  credentials preserve the presented refresh credential, and compare-and-set guards prevent an
  intervening login from being overwritten.
- Source commits `a2196be` and `f416359`; merged into `tideshift/main` as `7167cb5` and `32a004d`.

## Why now

Phase 3 of
`../lorehub-desktop/docs/work-packages/wp-desktop-commit0-cli-silent-auth-refresh.md` needs the
managed CLI to continue beyond the original authentication JWT lifetime without embedding
Commit0-specific formats or policy in Lore. The governing fork contract is
`../lorehub/docs/lore-change-requests/cr-020-client-authentication-refresh.md`. This unblocks the
Commit0 auth provider work and a later explicit managed-CLI release checkpoint; it does not publish
a CLI or complete the provider-side refresh handoff.

## Tests and gates

- `lore-credential`: 29/29 passed.
- `lore-transport`: 59/59 passed.
- `lore-revision` auth suites: 7 + 8 passed.
- Clippy was clean across all touched client crates with warnings denied; `cargo +nightly fmt
  --all` was clean.

Coverage includes lead-window boundaries, timeouts and keep-valid fallback, recipient checks,
same-identity serialization, different-identity independence, stale-waiter reload, process-death
lease release, cross-process nonce uniqueness, guarded atomic pair writes, initial login storage,
and publish-after-persist cache behavior. Detailed fixture notes live in `docs/testing-guide.md`.

## Reviewer findings

`lore-reviewer` classified the change [CLIENT] and returned clean with no blocking, correctness,
idiom, or test-gap findings. The residual risk where a server loses a one-time refresh handoff
response is platform-side, not part of Lore's reusable-or-rotating opaque credential contract.

## Notes

The DCO-signed source commits remain local to the fork branch/`tideshift/main` merge history. No
push or upstream EpicGames PR was made during this chunk.
