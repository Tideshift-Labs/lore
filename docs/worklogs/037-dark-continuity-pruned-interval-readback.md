# Dark continuity pruned interval readback experiment

**Date:** 2026-08-27
**Status:** Implemented and locally verified; not composed, deployed, or activated.
**Classification:** [SERVER]

Added the authenticated reconciler-only pruned interval v2 readback client after archive. The client
closes all 35 columns and validates exact namespace, revision, containment, and aggregate evidence.

An interval proves aggregate continuity for the bounded archived range. It is not per-operation
membership proof and does not replace the caller's local operation binding.

The regular suite passed 42 unit and 12 integration tests, with five live tests ignored. The exact
disposable PostgreSQL 16 mTLS archive-plus-read run passed 1, failed 0, filtered 4, in 4.15 seconds.

The fixture drove canonical `Begin` to `NO_LOCAL_EFFECT` under a temporary historical clock, then
restored the exact clock before archive and readback. It proved boundary-role denial and fail-closed
policy and namespace mismatch handling. All disposable resources were removed.

The synthetic fixture uses SHA-256 stand-ins for BLAKE3 and typed validators. The result is
client and procedure compatibility evidence, not cryptographic or production-readiness evidence.

The one-pass review found only a missing test pin for both SQL containment predicates. The tests
were added and rerun; no convergence review was performed.

No provider, cloud, deployment, composition, activation, readiness, or handoff work occurred.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
