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
- reading one exact shadow-release receipt by boundary, epoch, sequence, and token with typed absence
  and canonical digest/byte validation; and
- replacing one exact retention-eligible terminal detail with its bounded authenticated pruned
  interval, using the exact row and shadow-release-receipt digests plus a 1-byte-to-1-MiB local-
  dependency proof; and
- reading one boundary's current or historical epoch, continuity high-water, ownership counters,
  reconciliation state, and latest snapshot.

Mutations run in serializable transactions with server-enforced statement and lock timeouts. The
client makes exactly three attempts for known-aborted `40001` serialization failures and `40P01`
deadlocks, waiting 25 ms and then 100 ms. It never blindly retries a transport failure around
commit: it reconnects, performs the operation-specific authoritative read, adopts only an exact
committed result, replays only an exact prior or absent state, and otherwise fails closed. All
authoritative reads use bounded read-only transactions and are never retried. Unsigned 64-bit values
cross the PostgreSQL `NUMERIC(20,0)` boundary as canonical decimal text, and procedure results decode
through closed enum and digest allowlists.

## Embedded migration

`schema::CONTINUITY_MIGRATION_V1` embeds the exact 196,426-byte transactional migration used by the
independent authority. Its BLAKE3-256 is
`2b3664532b62cddbb94dbb83dde954fe121aecbc484e2f7190e153a61f38b003`. Runtime code never installs
the migration. Provisioning must install and read back separately attested bytes before readiness.

## Private protocol

The exact private `lore.object_dispatch.v1.ObjectStoreDispatchService` contract lives in
`lore-proto`. It has seven RPCs, including client-streaming upload and server-streaming result
fetch, with checked-in generated client and server bindings exported from
`lore_proto::lore::object_dispatch::v1`. A semantic declaration-token guard pins the package,
service, RPC streaming shapes, messages, fields, presence, oneofs, and enums.

The source-dark service shell implements all seven generated methods and immediately returns gRPC
`UNAVAILABLE` before inspecting a request or polling an upload stream. `FetchResult` fails before it
returns a stream. Every transport requires a client certificate from the configured CA. An exact
URI-SAN registry maps one certificate identity to one service instance, one provider boundary, and
a nonempty bounded cell set before a handler can run. Missing, invalid, expired, unregistered, or
ambiguous identities fail before the handler and record no source-dark RPC metric. The standalone
binary deliberately installs an empty deny-all registry; later deployment composition must inject an
accepted registry before any caller can reach a handler.

Pure injected validators exact-match the certificate-derived boundary/cell scope, authenticated
tenant, protocol and policy revisions, one ACTIVE unexpired cell allocation revision/fence, and one
cell-admission ID/fence. They use an injected database time, have no lookup client, and remain
unwired from the request handlers because the authenticated-tenant wire context and authoritative
allocation/admission read sources are not frozen. The shell has no continuity, spool, allocation
store, admission store, or provider dependency, so it cannot create durable state or authorize
traffic. Its rejection counter accepts only the seven frozen RPC names plus fixed `Unavailable` and
`source_dark` labels; arbitrary HTTP paths, methods, user agents, certificates, tenants, boundaries,
requests, buckets, and keys never become metric labels.

The standalone binary requires exactly:

- `LORE_OBJECT_DISPATCH_SERVICE_CONFIG_REVISION=object-store-dispatch-service-mtls-shell-v1`;
- `LORE_OBJECT_DISPATCH_LISTEN_ADDR=<nonzero loopback socket address>`;
- `LORE_OBJECT_DISPATCH_SERVER_CERT_CHAIN_PEM_PATH=<absolute path>`;
- `LORE_OBJECT_DISPATCH_SERVER_PRIVATE_KEY_PEM_PATH=<absolute path>`; and
- `LORE_OBJECT_DISPATCH_CLIENT_CA_PEM_PATH=<absolute path>`.

Every other `LORE_OBJECT_DISPATCH_*` key is rejected at this shell stage. TLS material is loaded only
from regular files at those runtime paths, with a 1 MiB bound per file, and is redacted from
diagnostics; no certificate or key is embedded in the image. There is no health or readiness
endpoint, provider route, provider credential, migration
installer, or loreserver composition. The local image supplies `127.0.0.1:50051`, runs as an
unprivileged user, exposes no port, and has no readiness `HEALTHCHECK`. Its three TLS path variables
and read-only secret mounts must be supplied at runtime; the image declares neither.

## Verification

```sh
cargo +nightly fmt --all -- --check
cargo clippy -p lore-object-dispatch --all-targets -- -D warnings --no-deps
cargo test -p lore-object-dispatch

# Local source-dark image only; do not publish or deploy it
docker build -f lore-object-dispatch/Dockerfile -t lore-object-dispatch:local .

# Explicit, disposable, preprovisioned PostgreSQL target only
cargo test -p lore-object-dispatch --test continuity_live -- --ignored --test-threads=1
cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_allocates_dedicated_drained_epoch_one_to_two
cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_archives_one_admin_seeded_retention_eligible_detail
```

The library suite validates service and continuity configuration, mutual TLS, URI-SAN registration,
allocation/admission fence validation, redaction, SQL procedure shapes, exact numeric transfer,
closed result decoding, migration identity, transient-error classification, and exact ambiguous-
commit reconciliation.
Each live contract has passed against disposable PostgreSQL 16 over real mTLS and the exact embedded
migration. Run the shared-fixture contracts serially or by exact test name; a parallel all-ignored
invocation can encounter expected serializable counter contention. They cover mapped boundary and
reconciler identities, typed absence, serializable mutations, exact transition replay and readback,
no-local-effect release, quarantine, ambiguous dispatch, both adjudication kinds through final
release, nonzero `pg_lsn` snapshot recording and
replay, covered `BOUND` ownership release, counter/readback invariants, and Begin replay of final
rows. The snapshot/release contract also proves exact four-part shadow-release-receipt readback,
canonical digest and byte validation, typed absence for each mismatched identity component, and
denial to the boundary runtime identity. The dedicated drained-epoch contract proves `1 -> 2`, zero
new high-water, active epoch reads,
historical reconciliation absence, local invalid-order rejection, and transient SQLSTATE `40001` on
a stale exact request; callers adopt the winner through epoch readback rather than replay. The
archive contract uses normal Begin-to-`NO_LOCAL_EFFECT` transitions under a temporary historical
database clock, restores the exact clock before archive, and proves singleton interval/prune
sequence, post-prune detail absence, and boundary-role denial. Archive/prune depends on the exact
release-receipt digest and reconciles response loss through the authenticated pruned-interval read.
Retirement response loss similarly reconciles through the authenticated retired-summary read or
exact active-interval checkpoint. The probe separately confirmed that a connection without a client
certificate is rejected.
The live harness uses mechanics-only SHA-256-as-BLAKE3 and typed-validator stubs; its snapshot
evidence is synthetic contract data, not provider-local integration evidence. Deployment readiness
still requires reviewed production BLAKE3 and typed validators, full cross-boundary negative
isolation, deployment-revision readback, provisioning, and activation.
