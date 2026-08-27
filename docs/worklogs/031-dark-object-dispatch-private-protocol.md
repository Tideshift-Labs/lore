# Dark object-dispatch private protocol

**Date:** 2026-08-27
**Status:** Implemented and locally verified; not composed, deployed, or activated.
**Classification:** [SERVER]

Added the frozen private `lore.object_dispatch.v1` protocol for WP-121's dark object-dispatch
boundary. The contract now gives the server-only dispatcher an explicit wire seam without exposing
it through Lore's public client protocol or admitting provider traffic.

The protocol contains 67 messages, 21 enums, and seven RPCs. `UploadPut` is client-streaming and
`FetchResult` is server-streaming. Checked-in generated Rust bindings and exports include six boxed
`prost` oneof paths, with an independent drift test covering the source-to-generated relationship.

Official `protoc` 36.0 regeneration reproduced the generated binding SHA-256 exactly:
`8D119AF50BC642025F2FF8BC123B042B059941455F3D0028FB2A1C33A6EACB16`. The final normalized proto
source SHA-256 is `8453175459B48EC5250F2282905AB4E25D7E66D8F102EF4EC9D04134869B48B3`.

The combined object-dispatch and protocol suites passed 53 tests, with the explicit continuity
live test still ignored by default; the complete `lore-proto` suite passed 22 tests. Formatting and
warning-denying Clippy also passed for the affected crates.

No composition, deployment, credentials, provider traffic, handoff, or activation occurred. The
protocol remains dark source for the next server-side composition slice.

Pointers: commit `7f869a2`,
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
