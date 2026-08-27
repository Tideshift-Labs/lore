# Dark object-dispatch request identity

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; not wired, deployed, or activated.
**Classification:** [SERVER]

The source-dark library now validates and canonically fingerprints bounded `ObjectStoreRequestV1`
requests, classifies exact idempotent replays, and supplies UUIDv7 and database-time deadline
checks needed by a future first-seen admission transaction. No handler or provider path uses it.

Validation precedes replay lookup and comparison. Classification consumes the actual request and
opaque validated artifact, then rechecks descriptor, preimage, digest, and field-7 binding before
returning first-seen, replay, or identity-reuse conflict. The cross-language golden is 401 bytes:
`a06dcf15928a3df8bd6db6b38980492e235460fb667f4be84cbd078b7e20e903`.

The gate passed 61 library, 15 continuity, 25 request, 14 `service_mtls`, and 17 `service_shell`
tests; five live tests were ignored. Four exact proto tests, warnings-denied all-target Clippy,
nightly fmt, and diff checks passed.

One-pass review found replay could trust stored fingerprints before rebinding field 7, malformed
metadata allowlists had the wrong error class, and tag-only tests missed payload layouts. Fixes made
replay fallible and fully rebound, classified malformed allowlists as invalid limits, and added
independent vectors for six operations, fragment/startup, decomposed UTF-8, and present-empty
optionals. Fingerprint, UUID version/variant, deadline equality, and overflow regressions reran
green; review was not rerun.

Deferred: serializable DB lookup/insert, authority readers, quota/shared-spool filesystem, handler
wiring, provider traffic, readiness, deployment, and activation.
Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/), [CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md),
and [WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
