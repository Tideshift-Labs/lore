# Dark direct continuity client

**Date:** 2026-08-27
**Status:** Implemented and locally verified; not composed, deployed, or activated.
**Classification:** [SERVER]

Added `lore-object-dispatch` as the Lore-side direct client for WP-121's independent continuity
database. This establishes the dark CR-033 authority seam without routing mutations through the
Lorehub control plane.

The client covers connection, begin, token lookup, bound, completed, and no-local-effect operations.
Mutations are serializable, preserve the full unsigned 64-bit domain, and keep decoding and retry
behavior closed. The crate embeds, but does not auto-install, the exact 193,646-byte migration:
`1530e511568b42b9368b1296eb6cdbaeecbc7f56a7838ac253bcbeb95434e6dd`.

Connections accept one DNS host and `sslmode=require`. Rustls verifies an explicit CA and requires
an explicit client certificate and key. Native TLS, insecure/plaintext fallback, and ambient trust
roots are excluded. Driver diagnostics and logs are redacted; background work uses Lore spawning.

The normal suite passed 31 tests with one live test intentionally ignored. That test passed when
explicitly run against disposable PostgreSQL 16, one-day certificates, and the exact migration. It
proved TLS DNS verification, client-cert role mapping, NOT_FOUND, serializable begin, replay and
lookup, no-local-effect release and replay, and the final read.

The probe drove fixes for begin ordering/signature, row/byte retention, NOT_FOUND representation,
and required text-to-domain double casts. Its container, volume, database, keys, and certs were
removed.

No cloud/provider work ran. Composition, deployment, traffic admission, and activation remain
deferred; this slice is dark source only.

Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
