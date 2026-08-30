# lore-object-dispatch

Server-only object-store dispatch authority primitives. The crate is dark source: it is not linked
into loreserver composition and cannot authorize provider traffic or first-seen admission.

## Composition: in-process cell authority

There is no separate dispatcher process, no in-cell mTLS service, and no surviving RPC (CR-033 D1,
2026-08-28). The cell dispatch authority is the retained PostgreSQL procedures below, installed in
the cell database and called directly by every loreserver replica and drain worker through a typed
Rust client linked into `lore-postgres`. That client consumes `lore-postgres`'s existing connection
pool rather than a separately configured one; the external-endpoint connection contract (single ASCII
DNS host, `sslmode=require`, pinned CA, mandatory client certificate) was written for an authority
database outside every cell and does not survive now that the authority is the cell's own database.
Redaction and the closed retry classification do survive: connection strings, PEM material,
PostgreSQL diagnostics, and parameter values never reach `Display`, `Debug`, `Error::source`,
tracing, or detached-task logs.

The bounded-execution envelope is retained verbatim on that pool: `SET LOCAL statement_timeout` and
`lock_timeout` inside every mutation and authoritative read; read-only transactions never retried;
mutations at exactly three attempts retrying only known-aborted `40001` and `40P01` after 25 ms and
100 ms, with the session released before sleeping; transport ambiguity around `COMMIT` resolved by
reconnect plus the operation-specific authoritative read, adopting only an exact expected committed
result and failing closed when the projection cannot prove either outcome.

`lore-proto`'s `lore.object_dispatch.v1` messages and enums are retained as the canonical record
schema the codecs below encode, not as a wire protocol; the seven-RPC `service` block and generated
server bindings, and the independent `ObjectStoreContinuity*V1` messages/enums, were removed with the
superseded continuity authority. `lore-proto/tests/v1_object_dispatch.rs` re-freezes a token/digest
drift guard over the surviving proto source in the same commit as any further proto edit.

## Embedded migration

The cell install set is migrations 0002 and 0003 (`retention_schema`/`retention_provisioning`, the
verified install prerequisites for the chain below) plus 0007 through 0017 (`local_authority_*`).
Migrations 0004 through 0006 (`retention_readback`/`retention_mutations`/`retention_prune_receipts`)
are deferred and not installed, alongside the pure compact-receipt, full-to-compact, and
compact-prune planners in `compaction.rs`, `full_to_compact.rs`, and `compact_prune.rs`: correct,
tested, sized for the former global ledger's row volume, and uncalled until CR-033 D5's cell-scale
retention sizing lands. Runtime never auto-installs any migration; a migrator role installs out of
band, through the concrete `cell-schema-install` binary described below (WP-114 CD-1), not by
hand.

`local_authority_schema::LOCAL_AUTHORITY_MIGRATION_V1` embeds the exact 42,294-byte source-dark
local authority core migration. Its BLAKE3-256 is
`d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff`. It extends the retention
namespace with requests, attempts, spool objects, quota usage, dispatchers, payload purges, and
fetch leases. Runtime code does not install it, and the artifact grants no direct table authority.

`local_authority_provisioning::LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1` embeds the exact
24,837-byte source-dark provisioning/readback migration. Its BLAKE3-256 is
`90900a392e8d6ca0b59c12aa735e6acf8da364319025b8fae4cafe88a51ed14d`. It freezes API
`object-store-dispatch-authority-provisioning-v1`, permits only the exact migrator to install, and
permits migrator or maintenance state readback through authorization-first `SECURITY DEFINER`
functions with a fixed `pg_catalog` search path. A frozen catalog manifest rejects schema,
constraint, index, function-security, policy, and ACL drift. Runtime code neither installs nor calls
this surface; direct table and column authority remains owner-only.

`local_authority_canonical_codec::LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1` embeds the exact
16,704-byte source-dark RESERVED/SPOOL_READY canonical-codec migration. Its BLAKE3-256 is
`b0803eacad028566e9fd5559f8f8069c44ad290d5631a8cef1a4f7c9669ea12a`. Eleven owner-only
`SECURITY DEFINER` helpers with fixed `pg_catalog` search paths construct and hash server-derived
canonical records; missing, NULL, or non-32-byte `public.blake3(bytea)` results fail closed. The
artifact creates no tables, mutation procedure, provider implementation, runtime call, or grant.

`local_authority_put_reservation_schema::LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1`
embeds the exact 4,690-byte source-dark PUT-reservation schema migration. Its BLAKE3-256 is
`56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67`. It adds 12 distinct,
all-or-none pre-Submit reservation and current-ACK fields to the spool table, including the exact
overflow-safe minimum expiry and canonical ACK suffix. The authenticated lookup index and table
authority remain owner-only. The artifact adds no function, mutation path, runtime call, provider,
or grant; the replacement provisioning/readback surface below attests the extended catalog.

`local_authority_put_reservation_provisioning::LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1`
embeds the exact 31,471-byte source-dark provisioning/readback migration for the extended authority.
Its BLAKE3-256 is `afe63db96bf286d1f04e6015eaf797e020b2fcbb2b13012224c66ef462d47248`.
The complete catalog manifest attests all authority relations, type/domain/composite objects, 29
functions, and ACLs; its SHA-256 is
`837aa8d2654cea2204e88fcc56d4cd291199c73829aa77c0e55b69544864e32c`. Exact install, replay,
and migrator/maintenance readback use the replacement versioned surface; superseded entry points
lose service-role execution. Runtime code neither installs nor calls it, and it adds no mutation,
provider traffic, deployment, readiness, or named handoff.

`local_authority_put_reservation_record_codec::LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1`
embeds the exact 10,874-byte source-dark canonical PUT-reservation lifecycle-record codec. Its
BLAKE3-256 is `b37116d9d87e49ad5c0051514e721a80d0c39f1c9dcaa51c19f7a77618ee6514`.
The owner-only codec constructs the initial `UNBOUND`/`PUT`/`RESERVED`/`RETAINED` record at revision
1 from database time, the exact minimum expiry, and a recomputed RESERVED ACK. Partial accounting
starts at zero; rows and concurrency start at one, including for a zero-byte PUT. This record is
distinct from the ACK. Hard input and record-size caps fail closed. The artifact adds no mutation
procedure, runtime call, provider traffic, deployment, readiness, or named handoff.

`local_authority_reserve_put_mutation::LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1` embeds the
exact 23,166-byte source-dark atomic ReservePut mutation. Its BLAKE3-256 is
`eb5d413b9d5dd5d45802b3acaca193cc6b5ac783e38a4c00002a9f9abf77ed7`. The runtime-only
`SECURITY DEFINER` procedure requires serializable isolation and locks schema state, the spool key,
then global, boundary, and cell quota scopes. One database clock drives inclusive UUIDv7 windows
and exact expiry. `CREATED` atomically persists the canonical ACK and lifecycle row and charges all
three scopes; exact `REPLAY` preserves stable protocol/intent identity while permitting current
policy, allocation, and clock inputs. Zero-byte PUTs charge one row and one concurrency unit. Caps,
low-water reserves, checked overflow, and digest-provider failure leave no partial state. Tables and
codec helpers remain owner-only. No service call, object-provider traffic, deployment, readiness,
or named handoff exists.

`local_authority_put_upload_progress_codec::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1`
embeds the exact 17,444-byte source-dark in-flight PUT upload-progress codec. Its BLAKE3-256 is
`f5361aa66c3e1bdced683040e3a405557a8d2d07f85a182e8e33867e208631a0`. The owner-only
generalized RESERVED-row codec preserves the initial record codec's bytes and digest exactly. A
progress snapshot must satisfy `0 < bytes < expected`, positive chunks, one file,
`chunks <= bytes <= chunks * maximum_chunk_bytes`, and `revision = chunks + 1`. ReservePut replay
during progress returns the unchanged ACK without another quota charge. Explicit revocation on the
v2 codec and both replaced `SECURITY DEFINER` functions prevents CREATE OR REPLACE from restoring
service-role execution. This artifact does not itself add a progress-transition mutation, fsync
proof, service call, object-provider traffic, deployment, readiness, or named handoff.

`local_authority_put_upload_progress_mutation::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1`
embeds the exact 10,942-byte source-dark nonfinal PUT progress mutation. Its BLAKE3-256 is
`f9bb0d0ed36689b6c15b9686108adc905cd8fe9839156e051fc443b09941078c`. The runtime-only
`SECURITY DEFINER` procedure requires serializable isolation and authenticates schema state, the
exact fields-1-through-8 identity, and the current RESERVED row before atomically replacing the
canonical record and incrementing bytes, chunks, files, and revision without changing quota. Exact
latest replay precedes expiry and maxima checks; expiry equality blocks new progress but not replay.
Typed gap, conflict, overflow, tamper, rollback, digest-provider, and schema failures preserve the
whole row and quota state. The procedure records a caller assertion that the contiguous nonfinal
prefix is already fsynced. It does not prove filesystem bytes/fsync, accept the final chunk, rename
payloads, call the service, authorize object-provider traffic, deploy, publish readiness, or name a
handoff.

`local_authority_put_spool_ready_codec::LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1` embeds
the exact 17,033-byte source-dark canonical PUT SPOOL_READY snapshot codec. Its BLAKE3-256 is
`180fed6b34db413c761e7dcd1e5250119aca5c50116977e8de54ca131408cf8c`. State 2 requires exact
ReservePut ACK authentication and emits the canonical SPOOL_READY row without changing quota,
including for zero-byte PUTs. Lifecycle-v1 projection remains byte-for-byte compatible;
lifecycle-v2 permits only exact SPOOL_READY replay. The owner-only artifact does not perform the
transition, write/fsync/rename filesystem data, call the service, authorize object-provider
traffic, deploy, publish readiness, or name a handoff.

`local_authority_put_spool_ready_mutation::LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1`
embeds the exact 13,373-byte source-dark runtime transition from RESERVED lifecycle 1 to SPOOL_READY
lifecycle 2. Its BLAKE3-256 is
`1bf102fce2e86f48eed6295e1349795564c4aae48aa5ac5d5af5ab5233b0462c`. The serializable
procedure requires the exact final index and current partial snapshot, complete expected size and
hash, a final delta within the chunk maximum, and database ready time before expiry. `APPLIED`
atomically writes the state-2 ACK and distinct canonical ready row, zeros partial counters, and
leaves quota unchanged, including for zero-byte PUTs. Exact replay reconstructs the final index as
`revision - 2` before maxima and clock checks and remains valid after expiry. Duplicate handles,
digest-provider failure, tamper, and overflow roll back the whole row and quota state. The caller
asserts prior durability; this procedure does not write, inspect, fsync, or rename filesystem
content, wire service/provider behavior, clean up, deploy, publish readiness, or name a handoff.

## Shared spool verifier

`LinuxSpoolVerifier` is a source-dark, read-only observer for derived shared-spool paths. It retains
the configured root descriptor and opens artifacts descriptor-relative with Linux `openat2`,
requiring beneath-root, no-symlink, no-magic-link, and no-cross-mount resolution. Only regular files
on the root device are accepted. Complete candidates are read through the opened descriptor under
the configured size bound, hashed with exact BLAKE3-256, and checked for stable size and identity
before an observation is returned.

Recovery classification accepts only observations bound to the verifier's root identity and the
exact derived paths. A replaced configured root, a different verifier root, changed file identity,
unsafe file type, or mismatched path fails closed. The verifier is unsupported outside Linux and
grants no write, cleanup, publication, ledger, quota, request, provider, deployment, or readiness
authority; callers must still revalidate candidate decisions under the authoritative row lock.

## Request contract

`request.rs`'s pure request-contract kernel validates and canonicalizes the complete seven-operation
descriptor, reservations, consumer context, authenticated scope, metadata, range/list/body bounds,
and optional durable PUT spool evidence. It derives the exact five-part durable request key and the
frozen `object-dispatch-fingerprint-v1` BLAKE3 fingerprint. Canonical lowercase RFC 9562 UUIDv7
identities are classified against an inclusive injected database-time window. One effect-free API
atomically validates the caller-supplied fingerprint and classifies absent identity, exact full or
compact replay, and identity reuse with a different fingerprint. Current authority, cell admission,
deadline, reservation, and PUT spool checks are first-seen-only prerequisites. The former
`authority.rs` module's checks (exact protocol/policy revision, exact cell, exact derived boundary,
nonnegative injected database time, and the cell's budget-configuration-revision pin) folded into
this validator (CR-033 D3); with one boundary equal to one cell, "validate the authority context" and
"validate the request" are the same operation.

These functions perform no database, spool, clock, provider, or network access; the typed cell-
authority client and drain workers call them, and call the retained PostgreSQL procedures for the
durable admission, ReservePut, and spool-ready transitions themselves.

## Governed provider client (WP-114 CD-5)

`provider_client.rs` is the crate's only place a provider attempt may be authorized: the cell
boundary binding, the PUT execution plan, and the charge-before-send kernel. It ships **no provider
SDK, no credential, no endpoint route, no database connection, and no lock**, and performs no
filesystem or network I/O. The two seams CR-033 D4 needs around a send — the charge authority and
the S3 transport — are traits with exactly one shipped implementation each,
`UnwiredChargeAuthority` and `UnwiredProviderTransport`, and both **fail closed on every call**.
Compiling or testing this module authorizes no provider traffic; it is not activation evidence.
`compaction.rs` exposes `pub(crate) provider_attempt_audit_is_valid` so the ledger calls the one
frozen audit predicate instead of restating it.

`ProviderAttemptLedger::new(provider_boundary_id, logical_request_id)` opens a ledger bound to one
boundary and one request; there is no `Default`. `execute` refuses an attempt naming a different
boundary or request with `LedgerRequestMismatch`, checked before the poison and no-dispatch guards
and before anything is charged or sent, without closing the ledger. `audit_for(logical_request_id)`
replaced `audit()` for the same reason, but it is a check, not a binding: `audit_for` refuses to
hand an audit to a caller naming the wrong request, yet `ObjectStoreProviderAttemptAudit` is a
public struct of public counters that `ObjectStoreCompactReceiptInput` accepts beside a
`logical_request_id` it never compares it against, so a correct audit can still attach to the wrong
receipt. Closing that is WP-114 CD-8's obligation. `GovernedProviderClient::authorize` is now
crate-private; `validate_attempt` (returning `()`) is its public replacement, and
`ProviderChargeRequest` has no public constructor and is deliberately not `Clone`, so a charge
authority cannot retain a chargeable value past the call — charging outside a ledger is unreachable
rather than merely discouraged. `record_no_dispatch` still cannot bind its proof:
`NoDispatchProofFields` carries no request identity, a WP-114 CD-6 obligation. See `WP-114`'s CD-5
section and CR-033 D4 for the governing spec and disposition; this file states only the module's
boundary.

## Out-of-band cell schema install (WP-114 CD-1)

`cell_schema_install.rs` and the one-shot `cell-schema-install` binary are the production install
path. The binary is an operator command, not a service: one connection, one action, one verdict,
exit. It has no listener, socket, RPC surface, or run loop, and nothing in runtime references it.

Preconditions the installer checks and refuses without:

- the connection's `session_user` is `object_dispatch_retention_migrator`;
- all four `object_dispatch_retention_*` roles exist;
- the migrator is a member of `object_dispatch_retention_owner` **with `INHERIT FALSE`**; and
- `object_dispatch_retention_owner` holds `CREATE` on the target database.

The non-inheriting membership is not a style preference. Every frozen migration opens with
`SET LOCAL ROLE object_dispatch_retention_owner`, so membership is required; but 0008's and 0011's
own catalog asserts reject any service role holding a table privilege on an authority table, and
`has_table_privilege` counts privileges reached through an inheriting membership. A plain
`GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator` makes the very first
install call fail with `DISPATCH_AUTHORITY_CATALOG_MISMATCH` while nothing has actually drifted.

```sql
GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator
  WITH INHERIT FALSE, SET TRUE;
GRANT CREATE ON DATABASE <cell> TO object_dispatch_retention_owner;
```

One further precondition, undocumented until a review pointed it out: **the cell database must hold
no `pg_default_acl` rows at install time.** The `default_acls` manifest section is database-scoped
on purpose, because a default privilege written without an `IN SCHEMA` clause has
`defaclnamespace = 0` and still reaches functions created in `object_store_retention`. The pinned
digest is therefore the digest of an empty `pg_default_acl`, which is what a freshly created
database has and what a disposable test container has, but not necessarily what a database
someone has already configured has. A cell that carries unrelated default privileges will fail
attestation. That is fail-closed, not a hole, but it is a real deployment precondition rather than
a property of the schema.

```sh
$env:LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL = "postgresql://.../<cell>"
cell-schema-install install    # apply the CR-033 D5 set in order, then attest
cell-schema-install attest     # attest only; writes no schema
cell-schema-install measure    # print the live catalog manifest digests
```

The URL is read only from the environment, so it never reaches a process argument list, and it is
never echoed, including on failure. Exit codes: `0` success, `1` refused or drifted, `2` misuse.

What `install` does, and what it refuses:

- a database with no `object_store_retention` schema runs the full plan: the thirteen frozen
  artifacts in order, with the retention, authority and put-reservation install procedures called at
  their exact points in the chain (0011 retires 0008's install entrypoint, so the authority layer
  must be installed before 0011 is applied);
- a database that already carries the schema is **never re-migrated**. It is attested first, and the
  run is refused unless every layer already attests. Forward migrations are one-shot, so resuming a
  half-installed chain blind is how a recoverable cell becomes an unrecoverable one;
- after any function replacement it issues the explicit service-role revokes itself. This is a no-op
  against a correct cell, because the frozen migrations already issue them, and it is what brings a
  cell whose ACLs were widened out of band back before attestation.

**If a fresh install fails part way through, drop and recreate the cell database.** The plan is not
one transaction and cannot be made one: each frozen artifact carries its own `BEGIN`/`COMMIT`, so an
outer transaction would be ended by the first artifact rather than wrapping it. Artifacts that
already committed stay committed. Every later run then refuses that database, which is the intended
behaviour. Forward migrations are one-shot, so there is no safe "continue from step k". CD-1
installs into a fresh cell database, so drop-and-retry is the recovery; a database that already
holds data is an operator decision, not an installer one.

`attest` verifies, in order: each layer's identity tuple as one all-absent-or-all-valid fact; the
live catalog manifest against a pinned per-section and whole-manifest BLAKE3 (relations, columns,
constraints, indexes, types, function definitions with `prosecdef`/`proconfig`, function ACLs, and
relation and column ACLs); that no service role retains `EXECUTE` on a replaced function; the
expected inert state; and that the retired readback entrypoints are in fact unreachable.

Two consequences worth knowing before reading a failure:

- **0003's readback now has a live caller.** It had none anywhere before this, which was the first
  half of WP-114 CD-1's caveat N2.
- **Both dispatch-layer readbacks are retired at full chain depth, for different reasons.** 0011
  revokes `object_store_dispatch_authority_read_state_v1` outright (`42501`). And 0011's
  `assert_dispatch_put_reservation_catalog_v1` manifests every function in the schema with no name
  filter, so once 0012 through 0017 add functions,
  `object_store_dispatch_put_reservation_read_state_v1` fails closed with `55000` on a fully
  installed cell. That is sharper than N2's "0012-0017 have no `read_state` procedure": the existing
  readback does not merely fail to cover them, it stops working. The Rust attester carries those
  layers instead. Whether a successor readback migration should exist is a CD-3 question; CD-1 does
  not add one, because a new procedure is a new migration.

The pinned manifest is a **PostgreSQL 16** pin: it carries `pg_get_functiondef` and
`pg_get_indexdef` output, whose exact rendering is a server-version property. A different major
version is expected to fail closed and needs a re-measured pin, not a relaxed check. Re-measure with
`tests/run-cell-schema-install-live.ps1 -Measure`.

## Verification

```sh
cargo +nightly fmt --all -- --check
cargo clippy -p lore-object-dispatch --all-targets -- -D warnings --no-deps
cargo test -p lore-object-dispatch

# Local-authority live tier: supported path (stands up disposable PostgreSQL 16,
# installs the CD-1 set, runs all nine by exact name, reports PASS/FAIL/NOT RUN)
tests/run-local-authority-live.ps1

# Cell-schema installer/attester live tier (WP-114 CD-1): five gates over the real
# migrator-role install path, on its own disposable PostgreSQL 16
tests/run-cell-schema-install-live.ps1
```

The library suite validates cell-authority configuration, canonical request fingerprinting, UUIDv7
and idempotency classification, first-seen prerequisites, redaction, SQL procedure shapes, exact
numeric transfer, closed result decoding, migration identity, and transient-error classification.
Each `local_authority_*` live contract, run by exact name against a disposable, separately
provisioned PostgreSQL 16 with the matching migration installed, proves that instance's procedure
signature, rows/bytes/retention semantics, typed absence, and replay safety against a real database
rather than only the embedded migration bytes agreeing with the client statically.

`run-local-authority-live.ps1` (WP-114 CD-2, Lore `1bb4ff7`) is the checked-in provisioning
harness for this tier, modeled on the retention client's runner
(`tests/run-retention-client-live.ps1`). Two independent clean runs: 9/9 PASS, exit 0, container
removed, dangling-volume count unchanged. It installs the CD-1 set into a dedicated
`local_install_chain_proof` database to run the WP-114 CD-1 inert-state assertion; the
`local_authority_put_spool_ready_mutation` live test separately self-installs the full chain via
compile-time `include_str!`. Full verification detail is in CR-033's "Verification: the retained
half's live-test provisioning harness" section.

Manual fallback — run one fixture directly against an explicit, disposable, preprovisioned
PostgreSQL target without the runner:

```sh
LORE_TEST_LOCAL_CODEC_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_canonical_codec -- --ignored --exact live_postgres_reserved_and_spool_ready_bytes_match_independent_rust_vectors
LORE_TEST_LOCAL_PUT_RESERVATION_SCHEMA_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_put_reservation_schema -- --ignored --exact live_postgres_enforces_put_result_shape_time_ack_and_service_acl
LORE_TEST_LOCAL_PUT_RESERVATION_PROVISIONING_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_put_reservation_provisioning -- --ignored --exact live_postgres_chain_install_replay_read_and_drift_fail_closed
LORE_TEST_LOCAL_PUT_RESERVATION_RECORD_CODEC_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_put_reservation_record_codec -- --ignored --exact live_postgres_row_bytes_match_independent_vector_and_invalid_inputs_fail
LORE_TEST_LOCAL_RESERVE_PUT_MUTATION_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_reserve_put_mutation -- --ignored --exact live_postgres_reserve_put_is_atomic_exact_and_replay_safe
LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_CODEC_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_put_upload_progress_codec -- --ignored --exact live_postgres_progress_codec_is_exact_and_replay_safe
LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_MUTATION_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_put_upload_progress_mutation -- --ignored --exact live_postgres_progress_mutation_is_atomic_and_replay_safe
LORE_TEST_LOCAL_PUT_SPOOL_READY_CODEC_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_put_spool_ready_codec -- --ignored --exact live_postgres_ready_codec_is_exact_fail_closed_and_replay_safe
LORE_TEST_LOCAL_PUT_SPOOL_READY_MUTATION_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_put_spool_ready_mutation -- --ignored --exact live_postgres_spool_ready_is_atomic_replay_safe_and_source_dark
```

An `--ignored` run with the environment unset exits early — that is **NOT RUN**, never passing
evidence. Prefer the runner; the manual fallback exists for isolating one fixture.

`run-cell-schema-install-live.ps1` (WP-114 CD-1) owns a second, separate disposable container. It
does not share CD-2's, because its tests connect **as** `object_dispatch_retention_migrator`, a real
LOGIN role with a non-inheriting owner membership, rather than as a superuser using
`SET SESSION AUTHORIZATION`. That is the production install path, and only a real login exercises
it. Its five gates are a clean install on an empty database, an idempotent re-run that neither
re-migrates nor moves the catalog, refusal on a truncated chain with the schema left exactly as
found, refusal on seven distinct catalog drift classes each caught in its own manifest section, and
the revoke-after-replacement path restoring the exact pinned ACL state. Verified 5/5 PASS.

Limitations, updated at CD-1: `object_store_retention_read_state_v1` (0003's readback) still has
no live caller among CD-2's nine `local_authority_*` tests, but `cell-schema-install attest` above
is now a live caller. The first of WP-114 CD-1's two named readback gaps is closed. The second is
not: migrations 0012-0017 still have no `read_state` procedure, and on a fully installed cell
0011's existing put-reservation readback fails closed (`55000`) rather than merely omitting them,
alongside 0011's outright revoke of the 0008 readback (`42501`). The Rust attester carries those
layers instead, behaviourally, not through catalog readback. Every cell-authority procedure the
typed client calls (WP-114 CD-3) still needs a live case in CD-2's harness before it counts as
evidence; the harness existing does not by itself supply that coverage.
