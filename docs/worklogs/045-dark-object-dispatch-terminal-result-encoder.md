# Dark object-dispatch terminal-result encoder

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; source-dark and effect-free.
**Classification:** [SERVER]

The pure terminal-result kernel now validates and canonically encodes only the selected protobuf
payload message. It excludes the envelope oneof discriminator, terminal-result ID, supplied size,
and supplied digest, then derives the authoritative size and BLAKE3 from the selected bytes.

The true bool payload is exactly `0801` (2 bytes) and hashes to
`16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720`.
An empty/default selected message is zero bytes and hashes to
`af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`.
The nested version-list golden is exactly 67 bytes:
`0a180a05617373657412027631180120ac022a0465746167300012150a04676f6e651202763020ffffffffffffffffff011a046469722f20012a046e65787432027632`.

Fourteen focused tests cover all eight closed payload arms, optional-presence wire distinctions,
list and metadata bounds, deterministic metadata ordering, byte handles, provider errors, detached
outputs, and redacted diagnostics. The full crate/proto tests, warnings-denied all-target Clippy,
nightly format, and diff checks passed; five live tests remained intentionally ignored.

One-pass review found that generated-enum conversion plus unspecified-only rejection could silently
admit a future generated provider class. The validator now names every accepted class explicitly
and rejects unknown or unspecified values; direct tests pin the closed set. Review was not rerun.

Deferred: terminal ACK/discard receipts, database and filesystem effects, handler wiring, provider
traffic, readiness, deployment, and activation. Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
