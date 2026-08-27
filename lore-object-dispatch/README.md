# lore-object-dispatch

Server-only object-store dispatch authority primitives. The crate is dark source: it is not linked
into loreserver composition and cannot authorize provider traffic or first-seen admission.

## Continuity client

`continuity` connects directly to the independent object-dispatch continuity PostgreSQL authority.
It accepts exactly one TCP DNS host with `sslmode=require`, verifies that DNS name through rustls
against an explicit root CA, and requires a matching client certificate and private key. There is no
plaintext, opportunistic TLS, native-root, IP-host, Unix-socket, password-only, or insecure-verifier
mode. Connection and TLS material is redacted from diagnostics.

`ContinuityClient` exposes the versioned stored-procedure surface for:

- allocating or replaying an exact continuity intent;
- reading an intent by boundary and token;
- binding an intent to durable local state;
- marking exact completion evidence; and
- marking a decisive no-local-effect outcome and release basis;
- quarantining an exact `INTENT` or `BOUND` row and recording `BOUND` dispatch ambiguity; and
- preparing and completing typed `NO_LOCAL_EFFECT` or `NO_DISPATCH` adjudication with exact binding
  and ownership-release evidence;
- recording exact local durability snapshot coverage and releasing covered `BOUND` or `COMPLETED`
  shadow ownership; and
- allocating an exact next epoch from the expected drained namespace; and
- reading one boundary's current or historical epoch, continuity high-water, ownership counters,
  reconciliation state, and latest snapshot.

Mutations run in serializable transactions. Unsigned 64-bit values cross the PostgreSQL
`NUMERIC(20,0)` boundary as canonical decimal text, procedure results decode through closed enum and
digest allowlists, and retry classification is limited to an explicit transport/SQLSTATE set. The
client does not retry operations itself.

## Embedded migration

`schema::CONTINUITY_MIGRATION_V1` embeds the exact 193,646-byte transactional migration used by the
independent authority. Its BLAKE3-256 is
`1530e511568b42b9368b1296eb6cdbaeecbc7f56a7838ac253bcbeb95434e6dd`. Runtime code never installs
the migration. Provisioning must install and read back separately attested bytes before readiness.

## Private protocol

The exact private `lore.object_dispatch.v1.ObjectStoreDispatchService` contract lives in
`lore-proto`. It has seven RPCs, including client-streaming upload and server-streaming result
fetch, with checked-in generated client and server bindings exported from
`lore_proto::lore::object_dispatch::v1`. A semantic declaration-token guard pins the package,
service, RPC streaming shapes, messages, fields, presence, oneofs, and enums. This wire surface is
still dark: no service implementation is composed into loreserver and no provider route or
credential is available to it.

## Verification

```sh
cargo +nightly fmt --all -- --check
cargo clippy -p lore-object-dispatch --all-targets -- -D warnings --no-deps
cargo test -p lore-object-dispatch

# Explicit, disposable, preprovisioned PostgreSQL target only
cargo test -p lore-object-dispatch --test continuity_live -- --ignored --test-threads=1
cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_allocates_dedicated_drained_epoch_one_to_two
```

The unit suite validates configuration, TLS material, redaction, SQL procedure shapes, exact numeric
transfer, closed result decoding, migration identity, and transient-error classification. The
regular gate passes 42 tests with zero failures and four intentionally ignored live contracts.
Each live contract has passed against disposable PostgreSQL 16 over real mTLS and the exact embedded
migration. Run the shared-fixture contracts serially or by exact test name; a parallel all-ignored
invocation can encounter expected serializable counter contention. They cover mapped boundary and
reconciler identities, typed absence, serializable mutations, exact transition replay and readback,
no-local-effect release, quarantine, ambiguous dispatch, both adjudication kinds through final
release, nonzero `pg_lsn` snapshot recording and
replay, covered `BOUND` ownership release, counter/readback invariants, and Begin replay of final
rows. The dedicated drained-epoch contract proves `1 -> 2`, zero new high-water, active epoch reads,
historical reconciliation absence, local invalid-order rejection, and transient SQLSTATE `40001` on
a stale exact request; callers adopt the winner through epoch readback rather than replay. The probe
separately confirmed that a connection without a client certificate is rejected.
The live harness uses mechanics-only SHA-256-as-BLAKE3 and typed-validator stubs; its snapshot
evidence is synthetic contract data, not provider-local integration evidence. Deployment readiness
still requires reviewed production BLAKE3 and typed validators, full cross-boundary negative
isolation, timeout and bounded retry policy, archive/prune, authenticated pruned-interval read,
retirement/readback client surfaces, and deployment-revision readback.
