# Dark continuity execution envelope experiment

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; not composed, deployed, or activated.
**Classification:** [SERVER]

Added the dark continuity execution envelope: bounded PostgreSQL sessions, exactly three mutation
attempts for serialization/deadlock failures, authoritative reconciliation after ambiguous commit,
and fail-closed handling for unknown outcomes.

The regular suite passed 61 unit and 15 integration tests, with five live tests ignored. Fmt,
scoped Clippy, and diff checks passed.

A disposable PostgreSQL 16.14 mTLS probe wrapped `Begin`, asserted server-side
`statement_timeout=5s` and `lock_timeout=2s`, raised SQLSTATE `40001` on the first two attempts,
and allowed the third. The observed sequence count was exactly three and the terminal token was
`NO_LOCAL_EFFECT` and released. Boundary-B read and `Begin` calls both failed with `42501`.

The one-pass review found that ambiguous-commit reconciliation could adopt a partially matching
result. Reconciliation now requires the exact precommit digest and result, fails closed for
incomplete projections, and releases the session before retry delays. Relevant gates reran green;
the review was not rerun.

The fixture used the exact migration but mechanics-only SHA-256 and always-true typed validators.
It did not simulate a real post-`COMMIT` socket cut or concurrent-winner timing, so this is client,
procedure, and retry-envelope compatibility evidence rather than production-readiness evidence.

The container, volume, certificates, keys, and temporary SQL were removed. No provider, cloud,
deployment, composition, activation, readiness, or handoff occurred. The next dark step is the
gRPC service, configuration, metrics, and local image shell.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
