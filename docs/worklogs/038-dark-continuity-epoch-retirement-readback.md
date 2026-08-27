# Dark continuity epoch retirement readback experiment

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; not composed, deployed, or activated.
**Classification:** [SERVER]

Added dark epoch retirement and authenticated readback around a serializable old-epoch interval.
Retirement replaces it with a canonical summary while preserving exact replay and readback. The
summary namespace is a checkpoint only.

The regular suite passed 49 unit and 12 integration tests, with five live tests ignored. The exact
disposable PostgreSQL 16 mTLS run passed 1, failed 0, filtered 4, in 4.21 seconds.

The fixture drove a normal historical `Begin` to `NO_LOCAL_EFFECT`, created the canonical admin
snapshot at LSN `0/1`, archived and read the interval, allocated epoch 2, then retired epoch 1. It
proved exact replay and authenticated readback, boundary-role denial, fail-closed policy and
namespace mismatch, and client rollback after a wrong-policy request.

The same run proved a changed-proof replay is rejected permanently and the retired old-epoch
interval is gone. This distinguishes canonical retirement from retaining mutable historical detail
behind the checkpoint.

The synthetic fixture uses SHA-256 stand-ins and always-true validators. This is procedure and client
compatibility evidence, not cryptographic or production-readiness evidence.

The one-pass review found no production defect. Two live-test gaps were fixed, and the exact live
test reran green; no convergence review was performed.

All disposable resources were removed. No provider, cloud, deployment, composition, activation,
readiness, or handoff occurred.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
