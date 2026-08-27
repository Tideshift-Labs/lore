# Dark object-dispatch shared-spool contract

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; no filesystem I/O, authority, or activation.
**Classification:** [SERVER]

The source-dark library now pins shared-spool layout revision `object-store-spool-layout-v1`,
opaque boundary tokens, request-hash fanout, PUT/result handles, and `.part`/`.blob` paths. Raw
provider-boundary bytes never become path components; the persisted token, full BLAKE3 digest, and
exact boundary bytes must remain bound or validation fails closed.

Recovery classification is pure and exhaustive across absent, reserved, ready, and released ledger
views. It returns only revalidation, publication, ready-commit, or cleanup candidates. Observations
carry a domain-separated binding to the exact derived handle, and no decision grants filesystem,
ledger, quota, cleanup, publication, or dispatch authority.

The independent `boundary` vector pins digest
`780fececcec1e37cb0e828e2d3eec17a7c076159d13ba315b8d613f07aa69c90`, token
`odsb_pah6z3goyhrxzmhifdrnh3wbpj6aoykz2e52gfny2yj7a6vgtsia`, and fanout `4f78`.
Twenty-one spool tests passed alongside 61 library, 15 continuity, 25 request, 14 `service_mtls`, and
17 `service_shell` tests; five live tests were ignored. Four proto tests, warnings-denied all-target
Clippy, nightly fmt, and diff checks passed.

One-pass review found digest leakage through derived `Debug`, publicly forgeable observations that
were not path-bound, and duplicated boundary derivation. Fixes added redacted diagnostics, opaque
handle-bound observations with pre-classification mismatch rejection, one derivation helper, and
vectors for adversarial UTF-8, cross-path evidence, ready-state branch errors, and redaction. Review
was not rerun.

Deferred: no-follow filesystem verification, serializable reservation and chunk accounting, quota,
cleanup/publication execution, handler wiring, provider traffic, readiness, deployment, and activation.
Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/), [CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md),
and [WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
