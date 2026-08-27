# Dark continuity reconciler live experiment

**Date:** 2026-08-27
**Status:** Implemented and locally verified; not composed, deployed, or activated.
**Classification:** [SERVER]

Added dark-client quarantine, ambiguous-dispatch, and prepare/complete adjudication. The disposable
PostgreSQL 16 experiment used the exact embedded migration with distinct boundary and exact
`object_dispatch_continuity_reconciler` mTLS identities; a no-certificate connection was rejected.

Both ignored live contracts passed. They proved `INTENT -> QUARANTINED -> PREPARE NO_LOCAL_EFFECT ->
COMPLETE/release` and `INTENT -> BOUND -> AMBIGUOUS_DISPATCH -> PREPARE NO_DISPATCH ->
COMPLETE/release`, including exact replay and readback.

The first probe observed two adjudicated no-dispatch operations, two adjudicated no-local-effect
operations, and one no-local-effect operation. All five released, producing 15 transition receipts
and five release receipts.

Review found that `Begin` replay returned the current row rather than the original `INTENT`. The
closed state/ownership matrix and final `Begin` replay handling now preserve the intended contract.
The regular suite passed 40 tests with two visible ignores; both live tests passed. Fmt, scoped
Clippy, and diff checks passed.

The mechanics-only SHA-256 `public.blake3` function and typed-validator stubs are not production
evidence. Containers, database, data and certificate volumes, and PEM/key files were removed. An
empty host temp directory and two older tooling directories remain because host policy blocks
`Remove-Item`.

No provider, cloud, deployment, composition, activation, or readiness work occurred. Snapshot,
release, read, epoch, and compaction behavior remain next.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
