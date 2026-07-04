# 003 — Scope RepositoryMetadataGet/Set to the caller's repository (CR-011)

**Date:** 2026-07-03/04
**Status:** Done (fork-side). Upstream PR not opened yet (user's say-so pending); branch
`cr-011-repository-metadata-authz` is ready.

## Summary

`RepositoryService` (v0 + v1) rides upstream's authn-only `JWTAuthnInterceptor` (the known
UCS-13506 gap) and, within it, the 4 `RepositoryMetadataGet`/`RepositoryMetadataSet` handlers did
no authz at all — they never even received `auth_url`. Any authenticated token could read the
metadata-pointer hash of, or CAS-write the metadata pointer of, an attacker-chosen repository.
Worse in *kind* than CR-010 (cross-tenant write vs read-only leak) but narrow in blast radius: a
read-only-field guard already limits the writable field to `description`, and `updated` must name
a blob already addressable in the target partition, so the practical impact is description
rollback/replay + CAS-contention DoS rather than arbitrary corruption. **[SERVER]** — low-risk, we
control the build.

## Why now

Governing spec: `../lorehub/docs/lore-change-requests/cr-011-repository-metadata-repo-scope-authz.md`,
source INV-AI, a direct follow-on from CR-010's sibling-service sweep (worklog 002), which flagged
this exact gap as first-priority.

## What changed

- Threaded `auth_url: Option<String>` (from `environment.endpoint.auth_url`) plus the
  `authorization` header into the 4 handlers — `lore-server/src/grpc/handlers/
  repository_metadata_{get,set}.rs` (v0) and `lore-server/src/grpc/repository/v1/
  repository_metadata_{get,set}.rs` (v1) — via their 2 service wrappers
  (`repository_service.rs`, `repository/v1/service.rs`).
- Each handler now, after the zero-repo check and before any store read/CAS, calls
  `check_repository_query_authorization(auth_url, authorization, repository_id.into())` when
  `auth_url` is `Some`, propagating `PERMISSION_DENIED` on failure. `auth_url: None` (auth-off)
  performs no check, same posture as the sibling services.
- Deliberately mechanism-consistent with the existing `repository_get`/`repository_query` sibling
  checks (the ReBAC `CheckUserPermission` callback), **not** CR-010's JWT `verify_authorization` —
  this service authorizes via ReBAC, not JWT `resources[]`. No interceptor swap, no proto change,
  no mint change.
- A belt-and-suspenders `verify_authorization`-when-`auth_url`-is-`None` fallback was considered
  and skipped per spec — would be inconsistent with the rest of the service.
- Commits: `bf8cb40` (fix, on `cr-011-repository-metadata-authz` branch off `main`), merged to
  `tideshift/main` as `ca70ea1`; `763aee9` adds the testing-guide record.

## Tests

`lore-test-specialist` added 12 new tests (deny / own-repo accept / auth-off, x4 handlers) in
`#[cfg(test)]` modules per handler, backed by a new `authz_test_support` module in
`handlers/repository_query.rs`: an in-process stub `UrcAuthApi` gRPC server (hand-rolled, since
`lore-proto` builds `auth_api` with `build_server(false)`) served via `serve_with_incoming` on a
pre-bound `TcpListener` (no readiness sleep, no rebind TOCTOU), plus tempdir
`LocalImmutableStore`/`LocalMutableStore` fixtures and a metadata seeder. The headline case is
own-repo ACCEPT — proof that a stock-Lore-CLI-compatible authorized caller still reads and
CAS-writes its own repo successfully. Deny tests seed a would-succeed payload and re-read the
pointer afterward to prove the CAS never executed. `cargo test -p lore-server` — 759 passed.

## Reviewer findings (lore-reviewer)

Shippable, zero correctness findings. Applied: stub-server readiness-sleep removal plus the
bind-then-rebind TOCTOU fix (serve on a pre-bound listener instead). Deferred: the
unauthenticated-remap branch of `check_repository_query_authorization` is untested (the stub only
returns allow/deny; judged low value).

## Gates

`cargo +nightly fmt --all` applied (test-code reflow); `cargo clippy -p lore-server --all-targets
-D warnings` clean. Workspace-wide `clippy` remains red on the pre-existing upstream
`lore-client/src/cli/commands/branch.rs:1369` collapsible-if lint — untouched CLIENT code,
deliberately left, same as noted in worklog 002.

Note for the record: a confirming full-suite re-run on `tideshift/main` post-merge was blocked by
a 100%-full disk (`target/` ~256 GB, `os error 112`). Green was established by the specialist on
the identical tree pre-merge (`bf8cb40`); the merge commit added no code of its own.

## Follow-ups created

- `docs/testing-guide.md` gained the CR-011 coverage record plus 3 generalizable gotchas: the
  `build_server(false)` hand-rolled-stub recipe, the ephemeral-port bind-once + `serve_with_incoming`
  no-sleep pattern, and the real-store-fixture-plus-seed pattern (commit `763aee9`).
- Open the upstream PR for `cr-011-repository-metadata-authz` once the user gives the go-ahead.
- This closes the first/worst instance of UCS-13506 flagged by CR-010's sweep; the workspace-clippy
  `branch.rs:1369` lint remains open (upstream-owned, out of scope here).
