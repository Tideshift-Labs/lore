# Dark object-dispatch ReservePut and upload contract

**Date:** 2026-08-27
**Status:** Implemented, locally verified, and reviewed; source-dark and effect-free.
**Classification:** [SERVER]

The pure object-dispatch library now pins no-dispatch proofs, ReservePut admission and state
evidence, and UploadPut stream identity and rejection details. These contracts make expiry,
cleanup, state transitions, and stream rejection deterministic before any database, filesystem,
handler, or provider integration is allowed.

The 102-byte no-dispatch vector hashes to
`a90a544776416d8e40c6dcdf430cc0b2145035d3abbbc27b73a14cf20afd5a01`. Upload identity pins the
189-byte digest `e31575eac60e155a503aea7da7a68a0539d4d43a46868860691e2320dd9c9df3`; the empty identity is
`f333bc170a848c109e91de3b43eb2b92d77c6059eaafdc5954474353600bf217`. The 105-byte mismatch and
empty rejection details hash to `93729fffe2d29234aed87fd7ac2fd5e6a0fbaa9fd4c1482fd2d02b76d6bd3f70`
and `a7231e5f5c4897f6513aef370fb3061df1677530c971502c137f4ad87e60f0ae`.

ReservePut recomputes persisted admission from the original database clock and bounds, uses
inclusive cleanup equality, and accepts exactly six of 80 state/evidence presence combinations.
Thirty focused tests passed: eight no-dispatch, twelve ReservePut, and ten upload. The full crate,
proto, warnings-denied all-target Clippy, nightly fmt, and diff gates passed; five live tests stayed
ignored because no disposable continuity PostgreSQL or credentials were supplied.

One-pass review found the public mismatch-detail builder could claim an arbitrary field 1 through 8.
The builder now derives the lowest mismatch from frozen and candidate identities, rejects equality,
and tests all fields plus a multi-field lowest-field case. Review was not rerun.

Deferred: serializable admission, concrete ledger schema, spool I/O, handler wiring, provider traffic,
readiness, deployment, and activation. Pointers: [`lore-object-dispatch`](../../lore-object-dispatch/),
[CR-033](../../../lorehub/docs/lore-change-requests/cr-033-server-object-dispatch-authority.md), and
[WP-121](../../../lorehub/docs/work-packages/wp-121-cell-capacity-placement-and-provider-strategy.md).
