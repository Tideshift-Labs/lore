# Dark continuity release-receipt readback experiment

**Date:** 2026-08-27
**Status:** Implemented and locally verified; not composed, deployed, or activated.
**Classification:** [SERVER]

Archive and prune work exposed a prerequisite contract gap: the archive request requires the exact
shadow-release receipt digest, but a caller cannot reconstruct it from its release request because
the digest also commits database time and four ownership-counter revisions.

Added an exact reconciler-only release-receipt readback keyed by provider boundary, authority epoch,
continuity sequence, and continuity token. Typed zero-row absence preserves retry-safe lookup without
granting table access. The procedure validates the stored canonical receipt and digest before
returning it, and the Rust client rejects identity drift.

The regular Lore suite passed 43 tests with four visible ignores. The mirrored SQL contract suite
passed 55 tests with 845 assertions. An exact ignored test passed against disposable PostgreSQL 16
over mTLS: one test passed, zero failed, three were filtered, in 0.28 seconds.

The live run proved release receipt readback and replay, exact-key absence, and boundary-role denial.
Reviews were clean. One low-severity note remains static-only: migrator and public denial were pinned
by SQL grant-shape checks rather than exercised in the live fixture.

The exact container, volumes, and generated fixture files were removed. The slice remains dark and
server-only. No provider, cloud, deployment, composition, activation, readiness, or handoff work
occurred.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
