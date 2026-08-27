# Dark continuity archive/prune experiment

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; not composed, deployed, or activated.
**Classification:** [SERVER]

Added the dark reconciler-only archive/prune client around the frozen bounded procedure. This closes
the client surface for retention-eligible terminal detail while preserving post-prune absence.

The release-receipt readback slice was a necessary prerequisite: archive authorization requires the
exact canonical receipt digest, which cannot be reconstructed safely from the original release
request.

Archive/prune is deliberately one-shot and non-replayable. A successful call deletes the detail it
would need to authorize an exact retry, so callers must read back modeled absence instead of
reissuing the request after an ambiguous outcome.

The disposable PostgreSQL 16 mTLS fixture used one canonical historical terminal row with released
ownership, a validated receipt, and retention eligibility established by fixture time. This avoided
weakening the production retention contract for the test.

The exact live run passed one test with zero failures and four filtered in 0.23 seconds. It proved a
single-row accepted interval, nonzero interval digest, prune commit sequence one, post-prune modeled
absence, and boundary-role denial. The regular suite passed 48 tests with five visible ignores.

The single review found two test-only coverage gaps, not a production defect. Boundary denial moved
before archive mutation, and requested-sequence coverage gained a direct unit test. Per the campaign
rule, no convergence review rerun occurred.

The exact container, volumes, and generated fixture files were removed. No provider, cloud,
deployment, composition, activation, readiness, or handoff work occurred.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
