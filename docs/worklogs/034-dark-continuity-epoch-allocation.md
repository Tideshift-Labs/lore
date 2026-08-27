# Dark continuity epoch-allocation experiment

**Date:** 2026-08-27
**Status:** Implemented and locally verified; not composed, deployed, or activated.
**Classification:** [SERVER]

Added the dark reconciler-only epoch-allocation client around the frozen serializable drained-CAS
procedure. This makes authority turnover explicit while keeping the slice server-only.

An exact ignored test passed against disposable PostgreSQL 16 over mTLS with the embedded migration
and a dedicated empty epoch-one boundary. It proved the `1 -> 2` allocation, zeroed counters,
readback, and local rejection of invalid epoch ordering.

The old epoch row remained as history while active reconciliation returned `None`. A stale exact
allocation request returned transient SQLSTATE `40001`; the caller then adopted the winner through
`read_epoch`. This is the required retry distinction, not an idempotent replay response.

The exact live run passed one test with zero failures and three filtered in 0.14 seconds. The regular
suite passed 42 tests with four visible ignores; formatting, warning-denying scoped Clippy, and diff
checks passed.

The local fixture used mechanics-only SHA-256-as-BLAKE3 and typed-validator stubs, so this is
synthetic client/procedure compatibility evidence rather than cryptographic or production proof.
The exact container, volumes, and all certificate and setup files were removed; only the same
policy-blocked empty temp directory remained.

No provider, cloud, deployment, composition, activation, readiness, or handoff work occurred.
Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
