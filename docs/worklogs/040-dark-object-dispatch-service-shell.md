# Dark object-dispatch service shell

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; not secured, deployed, or activated.
**Classification:** [SERVER]

Added the dark gRPC service, closed configuration and metrics surfaces, and a local container image
for object dispatch. This establishes an executable authority shell without yet granting it object
content or allocation authority.

The regular suite passed 61 library, 15 continuity, and 16 service-shell tests, with five live
tests ignored. All four exact protobuf contract checks passed, as did fmt, scoped Clippy, and diff
checks. Each of the seven RPCs returned `UNAVAILABLE` before reaching content handling; the shell
has no authority dependencies.

The final local image was
`sha256:6165b45324273c405ee2f476961ad7da94ab9f6a7c50e6560e88c69b31e5274b`. Its smoke run used
UID/GID 10001, received only the exact two supported environment variables, and exposed no port.
The smoke container and image were removed afterward.

The one-pass review found raw-path metric labels, non-Unicode environment handling, Docker context
and error-reporting gaps, unlocked base images, and missing context tests. Those findings were
fixed and the relevant gates reran green; the review was not rerun. The `cfg(unix)` non-Unicode
runtime test could not execute on Windows.

No TLS, health/readiness contract, provider traffic, deployment, composition, activation, or
readiness handoff occurred. The next dark slice is the service mTLS boundary and cell identity,
followed by allocation/admission fence validation.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
