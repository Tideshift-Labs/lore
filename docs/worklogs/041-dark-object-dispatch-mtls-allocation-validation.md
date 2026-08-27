# Dark object-dispatch mTLS and allocation validation

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; not deployed or activated.
**Classification:** [SERVER]

The source-dark service now requires mutual TLS before all seven RPC handlers. A trusted client
certificate must exact-match one registered URI SAN, service instance, provider boundary, and
nonempty bounded cell set. The standalone binary keeps an empty deny-all registry.

Pure validators now exact-match certificate scope, tenant, protocol and policy revisions, one
ACTIVE unexpired provider allocation revision/fence, and one cell-admission ID/fence. They remain
unwired because neither the authenticated-tenant wire nor authoritative read sources are frozen.

The full gate passed 61 library, 15 continuity integration, 14 `service_mtls`, and 17
`service_shell` tests; five live continuity tests were ignored. Four exact `lore-proto` dispatch
tests passed, as did warnings-denied all-target Clippy, nightly fmt, and diff checks.

The final local image was
`sha256:a40a0add5869e5aceb49e808fcdb06f61c321bd12ccc7720a8224b09b86a5d72`. Its smoke run used
UID/GID 10001, three read-only runtime TLS mounts, no exposed port, and no health check. The smoke
container and image were removed, leaving no residue.

The one-pass review found unbounded/nonregular TLS file reads and incomplete canonical authority
validation. The fixes bounded each regular TLS file to 1 MiB and required nonnegative database time
plus NFC revisions. Directory, oversized, malformed/mismatched PEM, negative-time, and non-NFC
tests were added and reran green; the review was not rerun.

No tenant wire, authority read source, admission, spool, provider operation, readiness, deployment,
or activation was added or exercised.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
