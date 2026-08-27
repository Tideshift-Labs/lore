# Dark continuity snapshot and release experiment

**Date:** 2026-08-27
**Status:** Implemented and locally verified; not composed, deployed, or activated.
**Classification:** [SERVER]
Added dark-client snapshot recording, covered shadow-ownership release, reconciliation-state reads,
and epoch reads. These APIs extend the authority contract without composing a service or admitting
provider traffic.

An exact ignored test passed alone against disposable PostgreSQL 16 with the embedded migration and
distinct boundary and reconciler mTLS identities. It proved snapshot creation and replay, covered
`BOUND` release and replay, ownership-counter decrement and readback, epoch and reconciliation
reads, and `Begin` replay after release. The same fixture campaign rejected a no-certificate client.

Running all ignored live tests in parallel hit expected `SERIALIZABLE` counter contention. The live
contracts therefore require their exact commands or a serial test runner; parallel aggregate green
is not a valid expectation for the shared counter fixture.

The regular suite passed 41 tests with three visible ignores. Review found no correctness risk and
requested a nonzero `PgLsn` fixture plus serial README guidance. The fixture LSN changed from zero to
one. Its exact PostgreSQL 16 mTLS rerun against the embedded migration passed one test with zero
failures and two filtered in 0.32 seconds, using `authority_lsn=1`.

The local fixture used mechanics-only SHA-256-as-BLAKE3 and typed-validator stubs, so this is
synthetic client/procedure compatibility evidence, not cryptographic or production readiness proof.
The exact container, both volumes, and all certificate, HBA, and setup files were removed again;
only the same policy-blocked empty temp directory remained.
No provider, cloud, deployment, composition, activation, readiness, or handoff work occurred.
Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/), [CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md),
and [WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
