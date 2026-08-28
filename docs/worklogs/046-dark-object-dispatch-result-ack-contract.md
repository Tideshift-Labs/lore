# Dark object-dispatch result ACK contract

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; source-dark and effect-free.
**Classification:** [SERVER]

The pure object-dispatch library now validates and canonically fingerprints terminal-result ACKs,
matches each proof arm to the stored consumer context, and constructs detached ACK receipts with
bounded purge ordering. The request consumer-context validator was shared with ACK validation so
operation legality, authenticated scope, optional presence, and closed durable kinds stay aligned.

Independent vectors pin all three proof paths. The fragment ACK is 377 bytes and hashes to
`fe757e1ceaebcbd1ec78756caba62bb2e11d918e2d322f56f67ba56ac11ba6dc`; the startup ACK is
322 bytes and hashes to `e0af2f0e4399ef1bc9083d7f43dbe98c81b75f0d9d2fdd126a82e7596d1e5728`;
the durable ACK is 373 bytes and hashes to
`014b0b53c943f5a2ddfd8e5f7e607aacee2eb583a2330b844ac55d1c632c9791`.

One-pass review found that the shared validator did not exhaustively close the generated operation
oneof, allowing a future operation to become durable-consumer ACK-valid without explicit review.
It now matches all seven current operations exhaustively. Review also found self-hashed startup and
durable vectors plus incomplete field mutation coverage; independent vectors, exact tag/framing
suffixes, and mutations for every proof field, digest, durable kind, and scope now close those gaps.
Review was not rerun under the convergence rule.

All gates reran green: 82 library tests; every integration suite, including 11 result-ACK tests;
five live tests intentionally ignored; four object-dispatch proto tests; warnings-denied all-target
Clippy, nightly format, and diff checks. No provider or runtime traffic, deployment, readiness,
handler wiring, database effects, or activation occurred.
Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/), [CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md),
and [WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
