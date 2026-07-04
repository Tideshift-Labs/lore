# 002 — Bind notification Subscribe to the JWT-authorized repository (CR-010)

**Date:** 2026-07-03/04
**Status:** Done (fork-side). Upstream PR not opened yet (user's say-so pending); branch
`cr-010-subscribe-authz` is ready.

## Summary

`NotificationService::Subscribe` registered a live event stream for whatever repository the
request **body** named, while `JWTInterceptor` only authorizes the repository named in request
**metadata** — no cross-check between the two. A valid read token for repo A could subscribe to
repo B's live events (branch ids/names, lock cleartext paths, user ids), a cross-tenant metadata
leak on shared hosting. Fixed by re-running the same authorization check against the body
repository before registering the subscriber. **[SERVER]** — low-risk, we control the build.

## Why now

Governing spec: `../lorehub/docs/lore-change-requests/cr-010-notification-subscribe-repo-authz.md`,
motivated by INV-AH §4.

## What changed

- `lore-server/src/grpc/notification_service.rs`: `Subscribe` now does `request.into_parts()`,
  reads the body repository, and — when the request extensions carry an `AuthorizationToken` —
  re-runs `verify_authorization(token, body_repo)`, returning `PERMISSION_DENIED` ("Not authorized
  to subscribe to this repository") before `sender.register`. Reusing `verify_authorization`
  (rather than a metadata-equals-body string check) deliberately honors wildcard and multi-resource
  tokens the same way the interceptor's own matcher does.
- Auth-OFF path unchanged: with no token present (service registered without the interceptor,
  `grpc/server.rs:701-705`), Subscribe still accepts — same posture as CR-004.
- Mirrors the existing storage `Copy` re-check pattern (`protocol/storage/copy.rs:143`,
  `grpc/storage/v1/copy.rs:146`), so the fix follows an established precedent in the codebase
  rather than inventing a new authz shape.
- Commits: `9048a7c` (fix, on `cr-010-subscribe-authz` branch off `main`) merged to
  `tideshift/main` as `4a85148`; `69100a1` adds the testing-guide record.

## Reviewer findings (lore-reviewer)

Ship-ready. Applied: wrap the streaming assertion in a timeout; add a `resources: None` deny
case. SPDX header deliberately left Epic-only — a one-function upstream security fix, not new
fork-owned code.

## Sibling-service sweep (spec requirement)

Explore-agent pass + spot-checks found no second vulnerable case:

- Storage `Copy` (v0 + v1) also takes a body source repo, but already re-checks via
  `verify_authorization`.
- Storage/Revision/ThinClient/Lock handlers operate on the metadata repo (`get_repository`).
- `RepositoryService` (v0 + v1) operates on body repo ids under the authn-only
  `JWTAuthnInterceptor` — this is upstream's known gap (UCS-13506); `repository_metadata_get`/
  `repository_metadata_set` have no repo-scoped check at all. Flagged as first-priority follow-up
  if that gap ever closes.
- `EnvironmentService` takes no repository.

Full table lives in the CR spec's "Landed" section (lorehub repo).

## Tests

`lore-test-specialist` added 7 unit tests in a new `#[cfg(test)]` mod in
`notification_service.rs`: deny non-matching resource, deny `resources: None`, exact-match +
`BranchCreated` delivery under a 5s tokio timeout, wildcard accept, auth-OFF accept, zero-repo
`failed_precondition` with and without token. `cargo test -p lore-server` — 753 passed on the CR
branch, the 7 new tests re-verified green after merge to `tideshift/main`.

## Gates

`cargo +nightly fmt --all` applied (one test reflow); `cargo clippy -p lore-server --all-targets -D
warnings` clean. Workspace-wide `clippy` is red for a **pre-existing** upstream lint in
`lore-client/src/cli/commands/branch.rs:1369` ("this `if` can be collapsed into the outer
`match`") — untouched CLIENT-path code, out of CR scope, left for a future upstream-sync or
separate fix.

## Follow-ups created

- `docs/testing-guide.md` gained the CR-010 coverage record + 3 gotchas: constructing gRPC service
  unit tests without a live server, `expect_err` not compiling on non-`Debug` streaming responses
  (use `.err().expect(...)`), and wrapping stream assertions in `tokio::time::timeout` by default.
- Open the upstream PR for `cr-010-subscribe-authz` once the user gives the go-ahead.
- The workspace-clippy `branch.rs:1369` lint remains open (upstream-owned, out of scope here).
