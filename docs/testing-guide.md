# Testing our Lore fork

This guide maps the deltas carried by `tideshift/main` to their most useful automated gates. Keep
chronological execution notes in `docs/worklogs/`; keep only durable testing knowledge here.

## Classify first: SERVER vs CLIENT

- **[SERVER]**: `lore-server`, `lore-aws`, `lore-postgres`, server-facing proto and storage code.
  We control the deployed build, so test against the topology we actually operate.
- **[CLIENT]**: `lore`, `lore-client`, `lore-revision`, and CLI behavior. These changes ship into
  user workstations and remain gated on upstream acceptance unless explicitly approved otherwise.

The classification is about where a change ships, not which repository contains it. A helper in
`lore-revision` used only by loreserver can still be server-only; a helper called by the desktop's
embedded engine is client-relevant.

## How tests are organized

- Unit tests live in crate-local `#[cfg(test)]` modules. Run `cargo test -p <crate> --lib`.
- Integration tests live under each crate's `tests/` and in `lore-integration-tests`.
- Infrastructure-gated Postgres/S3 tests are `#[ignore]`; run them with `-- --ignored` and the
  documented environment variables. An unset environment must never report an infra test as passed.
- After a conflict-heavy merge, build affected test targets before interpreting individual failures.
  Then run formatting and warnings-as-errors Clippy on the affected crates.

Baseline gates for a substantial fork merge:

```text
cargo +nightly fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --no-deps -- -D warnings
cargo test --workspace -j 4
```

Use narrower gates while iterating, but record any intentionally omitted live or platform-specific
tier in the worklog.

## Deployed storage topology: do not conflate capabilities

Lorehub does **not** provision one bucket per repository. A deployed storage cell uses one configured
S3-compatible bucket shared by all repositories assigned to that region/cell. Repository isolation
comes from Lore's repository/context associations and platform authorization, not bucket routing.

The retired `DynamoBucketResolver` and `DedupScope::Partition` represented an unused alternative AWS
mode. They are not our deployed topology and must not be reintroduced as if they were required for
tenant isolation. ADRs 00011 and 00017 retain the historical decision record but are superseded by
ADR 00018.

In both active stores, fragment representation is authoritative on the S3 object:

- `lore-aws` keeps global lifecycle state plus repository/context associations in DynamoDB.
- `lore-postgres` keeps lifecycle state plus associations in Postgres and maintains a rebuildable,
  exact metering projection. Missing projection rows are repaired from S3 object metadata or fail
  closed; they are never silently omitted from exact-looking totals.

Because staging had no durable user data during this cutover, its old bucket/database contents were
purged rather than migrated. Future production upgrades must not assume `CREATE TABLE IF NOT EXISTS`
will update an older check constraint or state schema.

## Fork-delta inventory

- **CR-004 write-permission enforcement [SERVER]**: mutating revision RPCs require write permission.
  Gate: `cargo test -p lore-server --lib grpc::revision::v1::service`.
- **CR-006 protected branch surfacing [SERVER]**: v1 branch reads expose the protected flag.
  Gate: `cargo test -p lore-server --lib grpc::revision::v1::branch_get`.
- **CR-007 Postgres stores [SERVER]**: Postgres lock/mutable/immutable stores with S3 payloads.
  Offline gates: `cargo test -p lore-postgres --lib`. Live gates are
  `tests/{lock_store,mutable_store,immutable_store,concurrency}.rs` with
  `LORE_TEST_PG_URL`, `LORE_TEST_S3_ENDPOINT`, and `LORE_TEST_S3_BUCKET`, run using `-- --ignored`.
  `ImmutableStore::get_metadata` must return the same stored fragment metadata and `MatchFull`
  result as a full query.
- **S3-authoritative `lore-aws` store [SERVER]**: one statically configured shared bucket, object
  metadata describing fragment representation, and global DynamoDB lifecycle state. Permanent S3
  errors are `Internal`, modeled absence is `AddressNotFound`, and retryable failures are `SlowDown`.
  Gates: `cargo test -p lore-aws --lib aws_error:: -j 4` and
  `cargo test -p lore-aws --lib permanent_service_error -j 4`.
- **CR-005 and CR-015 Lorehub hooks [SERVER]**: branch transitions plus resource lock/unlock emit
  `lorehub_notify`; lock hashes disambiguate event ids without changing payload shape.
  Gate: `cargo test -p lore-server --lib hooks` and
  `cargo test -p lore-server --lib grpc::lock_service`.
- **No-op push side-effect suppression [SERVER]**: a successful re-push of the current head emits no
  notification, hook, `branch_pushed`, or pushed-counter increment. Gates:
  `grpc::handlers::branch_push::tests` and `grpc::revision::v1::branch_push::test`.
- **WP-066 hook observability and bounded retry [SERVER]**: delivery counters label terminal
  outcomes; retry handles transport failures, timeouts, 429, and 5xx with bounded backoff while other
  4xx responses fail fast. Gate: `cargo test -p lore-server --lib hooks::lorehub_notify`.
- **CR-009 graceful drain [SERVER]**: QUIC, public gRPC, and HTTP participate in bounded drain;
  `/health_check` returns 503 while draining and `/drain_status` exposes state. Gates:
  `drain::`, `server::tests::wait_for_shutdown_tests`, `settings::tests`, `health_check::`, and
  `drain_status::`. Cross-process signal behavior remains a live/e2e responsibility.
- **CR-010 notification subscription authorization [SERVER]**: the repository in the subscribe body
  must match token authorization. Gate: `grpc::notification_service::tests`.
- **CR-011 repository metadata authorization [SERVER]**: v0/v1 metadata get/set and storage stats
  share `RepositoryAuthorizer`; auth-off remains allow-all. Gate:
  `cargo test -p lore-server --lib repository_metadata` and
  `cargo test -p lore-server --lib repository_storage_stats`.
- **CR-016 repository storage stats [SERVER]**: exact per-repository counts use associations plus the
  rebuildable Postgres metering projection. Cross-repository reuse counts independently for each
  repository. Gates: the Postgres immutable-store live tests and repository-storage-stats handler
  tests. `ReplicatedStore` and `GrpcReplica` intentionally inherit `NotSupported` until their wire
  protocols gain an equivalent operation.
- **CR-018 QUIC write enforcement and CR-019 push-lock enforcement [SERVER]**: both default off;
  enabled cells reject data-plane writes without write permission and pushes conflicting with a
  foreign lock. Gates: the storage-service permission tests and `collect_push_lock_conflicts` tests.
- **CR-008 thin-client sizes [SERVER wire]**: `TreeNode.size` is optional tag 4, `mode` is tag 5,
  and `Revision.total_size_bytes` remains optional tag 11. Protobuf field names are not on the wire;
  presence is required so an empty file's zero is encoded. Gates: `lore-proto/tests/v1_thin_client.rs`
  and thin-client revision-tree handler tests.
- **CR-033 private object dispatch wire [SERVER]**: `lore-proto/tests/v1_object_dispatch.rs`
  fingerprints the whitespace/comment-free declaration stream copied from WP-121 (three constants at
  lines 16-18: token length, FNV-1a64, DJB2-XOR64) and checks the fork-collision annotation. Re-freeze
  the three constants in the *same commit* as any proto edit. Regenerate with `protoc` before
  accepting a fingerprint change. Gate: `cargo test -p lore-proto --test v1_object_dispatch -j 4`.
- **CR-033 cell dispatch authority: continuity family and separate-process service shell removed
  [SERVER]** (2026-08-28 re-scope: the cell's own PostgreSQL is the one authority; see the CR-033
  record for exactly which modules and RPCs were removed, not this guide). Two testing lessons
  survive the removal: a module simplified rather than deleted, with **zero** prior `tests/`
  coverage of its own (its only exercise was through a sibling module that WAS deleted), needs fresh
  test files, not edits — `config.rs`/`metrics.rs` and the `authority.rs` fold (new coverage landed
  in `tests/request_fingerprint.rs`) are both this shape. And:
  `ObjectStoreCompactDependencyFloorKind::Continuity`'s wire value `5` is explicitly retained (D5)
  even though its sibling `ContinuityQuarantined`/`ContinuityAdjudicated` variants were removed —
  don't remove that variant chasing the rest of the family out.
  `ContinuityWireLimits`/`RequestStateWireLimits` were always one struct behind a `pub type` alias
  whose owning side can invert across waves — check current ownership before assuming a direction.
  Either way it's one struct: a test importing the alias needs a plain rename to the surviving type
  when the aliasing module goes, not a field-by-field rewrite.
  Symptom: a retained suite (`tests/canonical_id.rs`) breaks even though it never imports the removed
  module by name. Cause: it tests a crate-private helper (`contract::validate_canonical_id`)
  exclusively through *whichever public wrapper is convenient* (`auth::AuthorizedCallerRegistry`),
  and deleting that wrapper module breaks the suite without deleting the private helper it exists to
  cover. What to do: before declaring a module deletion's test-side cleanup complete, `grep` every
  symbol the deleted module publicly exported across all of `tests/`, not just files named after the
  module; re-point the character-class/behavior matrix through a surviving public caller with the
  same private-helper contract (here, `spool.rs`'s `SpoolLayout::derive_boundary_binding`) rather than
  losing the coverage.
  The pure ReservePut/no-dispatch/upload contracts remain unwired and effect-free. Their offline
  suites pin the no-dispatch and upload canonical goldens, all 80 ReservePut evidence-presence masks
  (exactly six valid), persisted admission recomputation, cleanup equality, lowest upload mismatch
  field, rejection shapes, and redacted diagnostics. Gate: `cargo test -p lore-object-dispatch
  --test no_dispatch --test reserve_put --test upload -j 4`.
  Terminal-result canonicalization is likewise pure and source-dark: encode only the selected
  protobuf payload message, without its envelope oneof tag, terminal ID, digest, or size fields.
  Pin independent bool/empty BLAKE3 vectors, the full nested version-list wire literal, optional
  scalar presence, closed provider classes, detached sorted metadata, and redacted diagnostics with
  `cargo test -p lore-object-dispatch --test terminal_result -j 4`.
  Result ACK canonicalization must validate the stored request consumer context before encoding the
  context-matched proof arm. Pin an independently derived full preimage and digest, all three proof
  tags, optional-presence equality, closed durable-consumer kinds, terminal tuple and byte-handle
  equality, the inclusive preimage bound, and ACK receipt purge ordering with
  `cargo test -p lore-object-dispatch --test result_ack -j 4`.
  Result discard must independently pin every fragment successor/removal/tombstone, startup, and
  durable cancellation/supersession preimage. Exercise closed raw enums, successor tuple shapes,
  checkpoint ordering, exact context/result binding, byte-handle presence, inclusive bounds, and
  receipt purge ordering with `cargo test -p lore-object-dispatch --test result_discard -j 4`.
  Result-disposition replay tests must supply deliberately invalid later clock, retention, payload,
  and fetch-lease projections. Symptom: an exact retry fails after policy or cleanup state drifts.
  Cause: replay was evaluated after mutable first-seen authority. What to do: require the stored
  same-kind fingerprint and receipt to win first, then separately pin both ACK/discard race orders,
  discard fence/drain planning, and disposed-before-discarded fetch classification with
  `cargo test -p lore-object-dispatch --test result_disposition -j 4`.
  Durable fetch leases and payload purge add two coupled source-dark CAS gates. Run
  `cargo test -p lore-object-dispatch --test fetch_lease --test result_disposition --test
  payload_purge -j 4`. The purge reservation's independent TypeScript/Rust golden is 461 bytes, and
  the drain matrix rejects any head evolution unless its revision delta exactly equals the open-lease
  decrement and its commit time is not older than the reservation. This remains pure `[SERVER]`
  source with no loreserver composition, provider traffic, credentials, or deployment authority.
  The nine `local_authority_*` live tests (the retained cell-authority half; CR-033 D5's install
  set is 0002, 0003, then 0007-0017) have a checked-in provisioning harness:
  `lore-object-dispatch/tests/run-local-authority-live.ps1`. Unlike the retention-client live
  tier, these tests call `tokio_postgres::connect` with `NoTls` -- no certificates, no
  `pg_hba.conf`, no `ssl=on`; the container runs with `POSTGRES_HOST_AUTH_METHOD=trust` and plain
  `postgresql://postgres@...` URLs. Eight of the nine self-provision: each idempotently creates
  the four `object_dispatch_retention_*` roles itself and installs its own required migration
  subset from its own `include_str!`'d copy of the migration file, so the harness only needs to
  hand each an empty fresh database. The one exception is `local_authority_canonical_codec.rs`'s
  live test, which installs neither roles nor migrations itself and documents its exact
  requirement in its own `#[ignore = "..."]` message ("requires disposable PostgreSQL with
  migrations 0002 and 0009 installed") -- the harness must pre-install precisely that pair, not
  the full chain, matching what the test's calls actually touch (0009's codec functions need only
  0002's schema/roles, not 0007/0008's dispatch tables). The harness also runs the full CD-1
  install set (0002, 0003, 0007-0017) once into its own dedicated database as first executed
  proof the post-deletion chain installs cleanly, and cheaply asserts CD-1's documented inert
  state: four of the five tables 0002 creates (the ones inert while 0004-0006 are uninstalled;
  the fifth, `object_dispatch_retention_schema_state`, is written by 0003's install procedure)
  exist, and none of 0004-0006's mutation/readback procedures (which nothing installed can call)
  are present. Run:
  `pwsh -File lore-object-dispatch/tests/run-local-authority-live.ps1` (add `-KeepOnFailure` to
  leave the labelled container up for debugging). All nine tests stay `#[ignore]`; the harness
  opts them in explicitly with `--ignored --exact <name>`, it does not un-ignore them, so the
  crate's baseline `cargo test -p lore-object-dispatch` ignored count is unchanged by this run
  (don't hardcode a count here — it drifts; list it fresh with `-- --list --ignored`).
  CD-1's out-of-band installer/attester itself (`lore-object-dispatch/src/cell_schema_install.rs`
  plus `src/bin/cell-schema-install.rs`, a one-shot operator CLI, not a service) has its own
  offline-only suite, `tests/cell_schema_install.rs` — no Postgres, no `#[ignore]`. It re-reads
  `migrations/*.sql` from disk independently of the module's own `include_str!` copies (so a
  frozen-bytes claim is checked against ground truth, not against itself), and pins: the exact
  13-migration install set against the on-disk directory (a future migration must be classified
  installed-or-deferred or the test fails); the interleaved 16-step install plan; each schema
  layer's install/read_state function names, revisions, and digest against the migration that
  creates them; the 3-entry `CREATE OR REPLACE FUNCTION` replacement inventory across 0012-0017
  (scanned by text, not hand-enumerated, so an unpinned replace/one dropped from the pinned list
  both fail); and a `local_authority_put_reservation_provisioning.rs`-style "runtime source never
  calls the install entrypoints" guard extended to the new bin target. Gate:
  `cargo test -p lore-object-dispatch --test cell_schema_install`. One test
  (`cell_schema_error_is_a_standard_redacted_error_type`) is a type-level stub pending the real
  `CellSchemaError` variant list, which the module's pinned contract deliberately left open —
  fill in the per-variant `format!("{e}")`/`{e:?}` redaction assertions once the enum lands.
  WP-114 CD-5's provider client (`provider_client.rs`): `AuthorizedProviderAttempt` is
  crate-private-constructed, and a transport reporting `provider_requests_issued != 1` poisons the
  ledger. That bounds what a transport may issue *and admit to*; it does not prove SDK auto-retry is
  off, because an SDK retry happens below the one call and reports one honestly. Disabling it is
  CD-6's construction obligation, and `ProviderRetryPolicy` is only the declaration. `record_no_dispatch`
  refuses after any issued attempt regardless of outcome (decisive or ambiguous) — a hand-listed
  audit-mirroring test missed the ambiguous case, and its successor matrix then missed it again by
  applying the no-dispatch only *before* the outcome sequence; generate such state matrices by
  driving the real API, and give a sequencing rule an axis on both sides of the sequence.
  `ProviderAttemptLedger::audit` calls `compaction`'s own `provider_attempt_audit_is_valid` rather
  than restating the algebra, which removes today's duplicate; nothing stops a future restatement,
  so keep the call. The matrix's pinned state set is a change-detector, not an oracle: it is
  invariant under swapping the decisive/ambiguous arms, so the two tests that pin that mapping
  directly are load-bearing rather than redundant with it.
  `validate_endpoint_host` accepts a single-label host (`minio`, `localhost`).
  Double pattern: one generic closure-scripted double per trait, `new` returning
  `(Self, Rc<Cell<u32>>)` — the double moves into the client, so the counter handle must outlive
  it; to capture a value the double *receives* rather than just count calls, close over an
  `Rc<RefCell<Option<T>>>` in the same closure instead of a bespoke struct. INV-EJ P1 (round 4):
  `ProviderAttemptLedger::new` now takes `(provider_boundary_id, logical_request_id) ->
  Result<Self, _>` (no `Default`), and `execute` refuses a request naming a different
  boundary/logical-request than the ledger is bound to with `LedgerRequestMismatch`, checked before
  `authorize` and unpoisoned — one ledger can no longer accumulate two requests' attempts.
  `authorize` is crate-private now; `validate_attempt` (`Result<(), _>`) is its public replacement,
  so a test asserting the `ProviderChargeRequest` an authority receives needs the capture-closure
  pattern above during a real `execute()` call, not a direct call. `audit_for(logical_request_id)`
  replaced `audit()` for the same reason the input is bound: bare counters could be attached to
  another request's receipt. Adding an identity field to a type whose `Debug` is `#[derive]`d is how
  this module's redaction regressed once — the ledger leaked both strings until the same round gave
  it the hand-written impl its siblings already had, and a test now guards it. Gate: `cargo test -p
  lore-object-dispatch --test provider_client -j 4` (no `#[ignore]`).
- **CR-021 AWS error honesty and retry [SERVER]**: the shared classifier preserves modeled absence,
  maps only retryable failures to `SlowDown`, and keeps permanent failures source-preserving
  `Internal`. SDK retry defaults to Standard, with Adaptive opt-in and Disabled as one attempt.
  Gates: `lore-aws` `aws_error::`, `clients::`, and permanent-service-error tests.
- **CR-021 fragment/read overload propagation [CLIENT-relevant]**: `SlowDown` survives fragment
  walks and the local-with-remote fallback boundary; genuine absence remains `AddressNotFound`.
  Gates: `cargo test -p lore-revision --test state -j 4` and
  `cargo test -p lore-storage --lib read::tests:: -j 4`.
- **CR-017/CR-020 authentication refresh [CLIENT]**: token pairs persist atomically, refresh is
  provider-neutral, failed refresh cannot publish partial credentials, and a full reset clears QUIC,
  gRPC, and exchanged-auth caches even when one cache is already empty. Gates:
  `cargo test -p lore-transport --lib`, `cargo test -p lore-credential --lib`, and
  `cargo test -p lore-revision --test auth --test auth_exchange`.
- **Native TLS roots [CLIENT]**: UCS auth trusts native OS roots while using the upstream network
  runtime. `cargo test -p lore-transport --lib` is a smoke gate; retain live TLS coverage.
- **Remote-proven explicit sync [CLIENT]**: the in-process Rust facade can mark an exact target as
  already verified remote. Only a same-branch, non-merge, first-parent advance repairs `LATEST` and
  last-sync, including a working-tree no-op. Generic explicit sync, CLI behavior, service
  serialization, and the C ABI are unchanged. Gate:
  `cargo test -p lore-revision --test sync -j 4` (backward, no-op, older-target, cross-branch, and
  forward-advance controls).
- **Exact-selection commit transaction [CLIENT]**: `lore-revision/tests/exact_selection_transaction.rs`
  pins the public transaction across mixed Add/Modify/Delete, metadata policy, source-digest and
  semantic admission failures, anchor preservation, immutable capture, token lifetime, staged-state
  repair, input limits before metadata reads, and committed-state deserialization. Private
  unreachable authority/map, exact byte-boundary, capped binary-read, and admission-before-publication
  branches are pinned by `exact_selection::tests`, including the production finalize-error mapping
  to the serialized public kind and stable code. Its real-store restoration cases wrap a
  tempdir-backed `LocalMutableStore`, inject failures at the production `store()` boundary, flush,
  drop and reopen the store, then reload branch/current/staged through their production loaders.
  A one-shot publication failure proves the durable originals and `anchors_restored: true`; a
  repeated restoration failure proves `false` and the durable partial state. `commit::tests` drives
  the narrower compensation helper, injecting failure at each authoritative anchor write.
  The Rust facade's independently acquired CLIENT token/context lifetime is pinned in
  `lore/tests/exact_selection_transaction.rs`. Gates:
  `cargo test -p lore-revision --test exact_selection_transaction -j 4 -- --test-threads=1` and
  `cargo test -p lore-revision --lib exact_selection::tests -j 4`,
  `cargo test -p lore-revision --lib commit::tests -j 4`, and
  `cargo test -p lore --test exact_selection_transaction -j 4 -- --test-threads=1`. Its actor-sized validation-only
  reread+MD5 measurement is deliberately `#[ignore]`; run the fully qualified test with
  `-- --ignored --exact --nocapture` and report environment/cache posture with descriptive timings.
- **Upstream revision-tree integration suite [mixed]**: the in-memory suite exercises batch fan-out,
  event ordering, multi-level/mixed-parent batches, concurrency, atomic rejection, and entry fields.
  Gate: `cargo test -p lore-integration-tests revision_tree_test -j 4`.
- **State-block local retention on remote fetch [CLIENT]**: `load_fragment`'s remote-fetch cache
  gate (`lore-storage/src/read.rs`) must key the always-retained exemption on
  `FragmentFlags::PayloadRevisionState`, not `PayloadLocalCachePriority`. The latter is a
  per-machine hint `lore-aws`'s `PAYLOAD_FLAGS` allowlist deliberately drops from the S3 object
  (`lore-aws/src/store/object_metadata.rs`'s `drops_state_store_location_and_per_machine_flags`),
  so a state block that relied on it surviving a round trip through the server silently stopped
  being retained after that allowlist landed, breaking every offline read (`revision info`,
  `status`) of a fresh clone. `PayloadRevisionState` is already pinned as surviving the round trip
  by `keeps_every_flag_that_describes_the_payload` in the same file — don't add a second pin for
  it. Regression + companion negative/positive cases:
  `cargo test -p lore-integration-tests --features integration_tests storage_remote_tests -j 4`
  (`get_caches_locally_when_payload_has_revision_state_flag` alongside the pre-existing
  `..._local_cache_priority_flag` and `get_falls_back_to_remote_on_local_miss`). Reuse this
  harness (`storage_remote_test.rs`'s `start_test_server`/`open_remote_handle`) for any future
  `load_fragment` gate case — it is the only place that exercises the gate against a real gRPC
  round trip rather than a wrapped local store.
- **Tree-block local retention [CLIENT], companion to the entry above**: the `lore-storage` fix
  alone was insufficient — `State::tree` (`lore-revision/src/state.rs`) reads the tree block
  through the same `load_fragment` gate, but the tree block does not carry
  `PayloadRevisionState`, so it needed an explicit `.with_cache().with_priority()` on its
  `ReadOptions` to survive a remote fetch, independent of `RepositoryRuntimeSettings::disable_cache`
  (defaults `true`). The tree read gates every delta/node/path read in the file (they all resolve
  it first), so this half is what actually made `revision info --delta` return file rows instead
  of a silently-empty list on a fresh clone. `lore-revision`'s test harness (`tests/*.rs`,
  `helper.rs`) has **no live-connected `RepositoryContext` fixture** — every test builds one with
  an offline session resolver (`Err(NoRemote)`), and `StorageSession::resolved` (the only
  constructor that can serve a real `get()`) is `pub(crate)` to `lore-transport`, unreachable
  without standing up a real server. So a full remote-fetch-then-cache regression for `State::tree`
  is not cheaply testable at this layer — don't invent a live-server fixture here.
  **Checked whether `lore-integration-tests` changes that answer: it doesn't, today.** That crate's
  real-server harness (`storage_remote_test.rs`'s `start_test_server`) wires only
  `immutable_store`/`mutable_store` into `GrpcServerBuilder` — no revision service, no
  resolve-by-name — and only ever drives the raw `lore::storage` C-ABI (`lore::storage::open`/`get`/
  `put`), never a `RepositoryContext`. Getting a `RemoteState::Connected` `RepositoryContext` at all
  means going through `lore_revision::repository::clone::clone`, which does a real
  `protocol::connect` handshake plus `repository::resolve_by_name` against the server and needs an
  actual committed revision already present there to clone — a full clone/repository fixture that
  does not exist in either crate's harness today. Building it is a real feature addition to the
  test infrastructure, not a cheap extension of `start_test_server`; deferred rather than built here.
  What's pinned instead, in `lore-revision/tests/state.rs`
  (`tree_read_options_request_cache_and_priority_despite_disable_cache_default`): the literal
  `read_options_from_repository(&repository).with_cache().with_priority()` expression `tree()`
  uses yields `cache: true, priority: true` even though a freshly constructed repository's
  `disable_cache()` defaults to `true`. Revert-checked (reverting `tree()`'s override in isolation
  leaves this test green) — record plainly that this test cannot catch a regression that drops the
  override from `tree()`'s own body without touching the expression elsewhere; that gap is open by
  design, not an oversight.
  **This half is not left unguarded, though** — its real automated regression guard is
  `webdriver_fullstack_history.rs` in `lorehub-desktop`'s full-stack WebDriver tier (a different
  repo, a slower tier), which asserts the History view renders the full chain plus expanded
  ancestor deltas on a real sparse clone and fails if the tree block is not retained, because the
  delta read is swallowed and the file list comes back empty otherwise. Ran green (1 passed / 0
  failed) against this fix. Fork-side coverage of the tree-retention half is deliberately deferred
  to that tier, not absent by oversight — a future reader of this guide should draw that conclusion,
  not "unguarded."

- **`revision info --delta`'s delta-read-failure surfacing [CLIENT]**: a failed
  `State::delta_block` read (`revision/info.rs`) now sends a mid-stream, non-terminal
  `LoreEvent::Error` naming the revision instead of silently emitting zero
  `RevisionInfoDelta` rows; `info()` still returns `Ok(())`/status 0 (deliberate -- a sparse
  clone legitimately lacks an ancestor's delta block offline, and lorehub-desktop's History
  view must not flip to an error state on it). A genuinely empty revision (zero `hash_delta`)
  must still emit neither delta rows nor an error event -- `lore_storage::read::load_fragment`
  short-circuits a zero-hash address to `Ok(empty)` before ever touching the store
  (`lore-storage/src/read.rs`'s `zero_hash_address_short_circuits_to_empty_without_touching_store`
  pins this, proven with a store wrapper that fails every `get()` and asserting zero calls).
  Gates: `cargo test -p lore-revision --test info -j 4` and
  `cargo test -p lore-storage --lib read::tests::zero_hash_address_short_circuits_to_empty_without_touching_store -j 4`.

- **CR-029 domain schema, receipts, outbox-base, backfill, bypass guard [SERVER, WP-116 Phase 2/3]**:
  the Postgres-owned repository/branch lifecycle, generation, tombstone, and operation-receipt rows
  under `lore-postgres/src/domain/` (`schema.rs`, `schema_mediated.rs`, `outbox/`, `backfill.rs`,
  `receipts.rs`, `bypass.rs`, `store.rs`/`PostgresDomainStore`). Tests:
  `lore-postgres/tests/domain_schema.rs` (bootstrap idempotence, CR-007 coexistence,
  tombstone-evidence CHECKs, R-BLOCK-3 case-folding pair, name release, identity non-reuse, quota
  bounds, schema-state gating, same-database identity), `domain_receipts.rs` (the receipt
  state-machine CHECKs), `domain_outbox.rs` (F-032-2 base conformance: payload cap,
  `(cell_id, idempotency_key)` retry, state enum, atomic rollback, restart survival),
  `domain_backfill.rs` (restart-after-failure parity against a clean run, no-op rerun, R-SHOULD-7
  residue classification via a fake `DomainBackfillSource` — the real source lives in `lore-server`
  and deliberately isn't reachable from this crate), `domain_migration_parity.rs` (catalog-level
  parity between `migrations/0001_init.sql` applied wholesale and `PostgresDomainStore::connect`'s
  boot-time path, via `pg_get_constraintdef`/`pg_indexes` so it only fails on real semantic drift, not
  formatting), `domain_mediated.rs` (schema_mediated.rs invariants that can't be a single-table CHECK:
  the fence-to-tombstone atomic exchange commits or rolls back together, and the documented catalog
  backstop on `lore_domain_tombstone_marker_prune_ranges` — exact duplicated `start_sequence`/
  `end_sequence` collide, but a general overlap sharing neither exact bound does **not**; true
  non-overlap depends on a namespace-row-lock discipline with no merge/insert function in this crate
  yet to test, and that gap is deliberate, not an oversight — see the file's own docs before assuming
  it's fixable from this side), `domain_bypass.rs` (R-SHOULD-4: `PostgresMutableStore`'s
  `.with_domain_enforcement(..)` wiring actually rejects the five lifecycle key types plus `Instance`
  on both `store`/`compare_and_swap` once enabled, never fences `Resolve`/`Untyped`, and toggles live
  on one shared handle with no reconnect — `bypass.rs`'s own unit tests already cover the pure
  classification/reversibility logic, so this file is deliberately about the wiring, not a duplicate),
  `domain_receipts_lifecycle.rs` (the async `prepare`/`consume`/`commit_terminal`/`receipt_get` state
  machine in `receipts.rs` — all five temporal classes, exact-retry token stability, per-field binding
  mismatch, single-use consume scoped to key+binding, hard-TTL expiry, terminal immutability, the
  future-reject quota's two limits, and future-marker binding scoping). Build a UUIDv7 at a precise
  offset from a captured `admission_clock` with `Uuid::new_v7(Timestamp::from_unix(NoContext, secs,
  nanos))` rather than sleeping. The future-reject quota keys on
  `(verified_issuer, authenticated_subject, tenant_scope_key)` with no `operation_id`, so a quota-limit
  test needing two prepares under the *same* namespace must reuse the seed call's exact
  `verified_issuer`/`authenticated_subject` — a second `fresh_key()` call mints an unrelated random
  issuer even when the caller intends "same tenant," landing the second prepare in an empty quota
  namespace instead of the exhausted one (confirmed: both quota tests passed for the wrong reason —
  a fresh empty quota — until fixed with a `same_namespace_key(base, operation_id)` helper that copies
  the identity fields and varies only `operation_id`).
  `domain_obliterate_fence.rs`
  covers `begin_obliterate`'s generation fence both ways (live advances by one; tombstoned refuses
  with `TOMBSTONED_V1`, generation unchanged) plus push-versus-obliterate agreement: `branch_push_commit`
  refuses the pre-obliteration generation and accepts the post-obliteration one.
  Gate: `cargo test -p lore-postgres --test domain_schema --test domain_receipts --test domain_outbox \
  --test domain_backfill --test domain_migration_parity --test domain_mediated \
  --test domain_bypass --test domain_receipts_lifecycle --test domain_obliterate_fence \
  -- --ignored` under `LORE_TEST_PG_URL`.
  Migration-parity and backfill each create a throwaway database because their whole-catalog scans
  cannot isolate shared fixtures. Most other cases use random identities in one database. The 20
  maintenance cases use `tests/run-domain-maintenance-live.ps1`, with a distinct database per case.
  Mediated-schema setup seeds the singleton global counter at revision 0/quota 1; first
  materialization provisions the org row at revision/count 0 and atomically charges both. A
  capacity-revision rejection case must reread the seeded revision before submitting a mismatch.
- **CR-030 lock fencing [SERVER, WP-117]**: `tests/run-lock-fencing-live.ps1` is the only evidence,
  and its `$inventory` is the definition of what ran — read it there rather than from a count
  written down here, which is how INV-EE P2-4 caught this entry restating a stale number inside its
  own fix. It spans four targets: `domain_lock_fencing.rs`, migration/runtime parity,
  `domain_obliterate_fence.rs` (whose push leg needs SCHEMA-117), and `lore-server` library cases
  covering the never-migrated boot regression, both CR-019 bypasses, and the fenced owner-pair push
  set. Each gets a fresh database, and `Assert-ExpectedCatalog` fails the run when the compiled
  catalog and the inventory disagree — fully for the three `lore-postgres` targets, and for the
  shared `lore-server` library only under the module prefixes this runner owns, so a case added
  under a module it shares with another package (`grpc::handlers::branch_push::tests::`) is still
  policed only if pinned by name. A case outside the inventory is NOT RUN however green a plain
  `cargo test` looks; that is exactly how INV-EE P1-3's
  broken regression stayed unexecuted. Batch tests need distinct earlier-sorted keys plus a shared later
  key (three rows expose a committed loser). Receipt-first tests block the repo row and expect
  SQLSTATE 55P03 from a receipt `FOR UPDATE NOWAIT`; lease tests hold the namespace lock past the
  lease, then require a full lease. Offline, `lore-server/tests/wp117_push_witness_wiring.rs` pins
  unconditional capture, the fenced-cell routing that leaves no ungoverned push on the legacy guard,
  and the single test-only bypass of the WP-120 arming gate;
  `grpc::handlers::branch_push::governed_tests` runs `publish`'s outcome mapping and CAS-retry
  suppression (P1-10) offline against `crate::domain::test_support::ScriptedDomainStore` (records
  every `branch_push_commit` input, every other method `unreachable!()`).
- **CR-029 WP-116 Phase 4, gRPC metadata carriage, status mapping, and the admission gate
  [SERVER]**: offline, no Postgres. `domain_operation_metadata.rs`'s `extract`/`require` (R-BLOCK-2's
  one-reader header contract) and `scope_key_*` (R-BLOCK-5) are pinned in an inline `tests` module:
  absence vs. every partial-carriage combination, wrong-length/version/non-UUIDv7 rejection, and
  divergent-vs-identical duplicate headers. `grpc/mod.rs`'s
  `map_domain_error_to_status`/`map_domain_rejection_to_status` are pinned in a
  `domain_error_mapping_tests` submodule of that file's existing `tests` mod, including the R-BLOCK-1
  pin: convert a mapped `OutcomeUnknown` status through `lore_transport::error::ProtocolError::from`,
  assert not `Disconnected`, with `Code::Unknown`/`Code::Unavailable` pinned positive as the replay
  arm so the test can't pass vacuously. The `urc-` guard in `checked_identity`/`scope_key_mediated` is
  a **prefix** check on each raw component, not substring-freedom over the encoded key — a
  `principal_user_id` embedding `urc-` past its first four bytes is accepted verbatim; test that
  boundary as its own pinned case, not inside a "never contains `urc-`" property loop over realistic
  inputs. `src/domain.rs`'s `DomainContext::admit`/`admit_at_entry`/`resolve_enforcement` need a
  `DomainTransactionStore` to construct — the trait doc anticipates a test-only fake, every method
  implemented explicitly (`unreachable!()` bodies; no trait default), since `admit` never calls the
  coordinator. Contract: carriage with no verified-principal token is `Unauthenticated` **regardless
  of enforcement** — pin that at both settings, since enforcement-off is not a licence to ignore
  carriage. `domain.rs`'s test-only `UnreachableDomainStore`/`context()` moved out of `mod tests` into
  a sibling `#[cfg(test)] pub(crate) mod test_support`, so any gated handler's own test module can
  build a real `Some(&Arc<DomainContext>)` via `crate::domain::test_support::context(enforcement)`
  without duplicating the trait impl — use this for the `Code::Unimplemented`-refusal proof (a gated
  handler test needs a *present* coordinator, not `None`, to ever reach
  `reject_unwired_governed_operation`; every handler test before this defaulted to `None` and so never
  exercised it). Pair it with a small `PanicOnAnyCallMutableStore` (or a wrapper that delegates reads
  and fails only `store()`) so the assertion also proves zero store access, not just the status code.
  The three self-heal writers (`repository_query.rs:134`, `branch_list.rs:116`,
  `repository/v1/repository_get.rs:147`) that write `RepositoryId`/`BranchId` mappings from read RPCs
  are deliberately ungated because they swallow their write error; that swallow is now pinned
  per-site with a `FailStoreWritesMutableStore`-style wrapper (delegates every method except `store()`)
  proving the RPC still returns `Ok` — a companion to the guard-rejects-the-write proof already in
  `lore-postgres/tests/domain_bypass.rs`. Gate: `cargo test -p lore-server --lib grpc::domain_operation_metadata
  grpc::tests::domain_error_mapping_tests domain::tests grpc::handlers::repository_metadata_set
  grpc::repository::v1::repository_metadata_set grpc::handlers::repository_query
  grpc::handlers::branch_list grpc::repository::v1::repository_get`.

## Durable test patterns and gotchas

### Build and merge hygiene

- A signature change in production code can leave direct handler tests stale. Build test targets
  after a merge, even when production targets compile. Concrete case: `lore-integration-tests`'s
  `remote_store_test.rs`/`storage_remote_test.rs` both called the pre-CR-018
  `GrpcServerBuilder::with_jwt_verifier(None)` (one arg) after `with_jwt_verifier` gained an
  `enforce_write_permission: bool` parameter — a plain `cargo build` never caught it because
  neither file is reached by the default (non-`integration_tests`-feature) build; only
  `cargo test -p lore-integration-tests --features integration_tests` does. Both are auth-OFF
  harnesses (`jwt_verifier: None`), so the bool is a no-op per the method's own doc comment — pass
  `false` for clarity.
- If an untouched file reports an impossible macro/import/rlib error after alternating Clippy and
  test builds, suspect stale incremental state. Clean only the affected crate before escalating.
- Regenerate protobuf output and `Cargo.lock` from their sources; do not hand-splice generated files.
- A large prost `oneof` can fail `clippy::large_enum_variant` after generation. Box every large
  branch through `Config::boxed`; the matching path includes the oneof name
  (`.package.Message.oneof_name.field_name`), not only the message and field. Regenerate, then pin
  the checked-in `Box` shapes so a toolchain/configuration drift cannot silently restore the lint.
- Check which `clippy.toml` governs the crate. A crate-local file shadows rather than extends the
  workspace configuration.
- After rebasing exact selection over an upstream stage/state rewrite, a compile failure at
  `file_modified_time_clear` means a normalized `String` path still crosses an API that now requires
  `RelativePath`. Convert fallibly before clearing the witness, then run
  `cargo test -p lore-revision --test stage_topology -j 4`; this compiles the seam and exercises the
  public multi-worker stage-through-commit lifecycle.

### Deterministic async tests

- Use `#[tokio::test(start_paused = true)]` and `tokio::time::advance` for timer-driven behavior.
- Use near-zero retry policies for behavioral tests; keep one explicit real-default test when the
  default delay itself is part of the contract.
- Exact-selection lifecycle callbacks provide deterministic filesystem fault points without a
  production-only test hook: `FileStageEnd` is immediately before the selected-file pre-capture
  read, while `FragmentWrite` is after immutable capture and before admission. Use the former to
  remove an Add and assert `PreFragmentationFileRead`; use the latter to mutate working bytes and
  assert the committed immutable payload remains the captured version.
- A rejected exact-selection attempt must be followed by another attempt in the same fixture.
  Symptom: the second call reports a stale parent instead of its typed validation error. Cause: the
  rejected staging pass left unpublished parent/revision metadata in memory. What to do: assert all
  current/staged/branch anchors after every rejection and retain at least one sequential-retry case.
- An Add has no prior file node. Symptom: inherited metadata lookup returns an internal node-not-found
  error. Cause: treating absence as a metadata read failure. What to do: include an Add with
  `FileMetadataSelection::Unchanged` and require zero inherited metadata.
- Exact-selection path, metadata, and aggregate limits are UTF-8 byte limits. Pin both the exact
  accepted boundary and one byte over with multibyte strings, including the commit message in the
  aggregate. A public case should put a missing binary source before a later oversized value and
  still receive `InvalidInput`, proving bounds run before filesystem metadata/read work. Exercise a
  sparse binary source at `MAX_BINARY_METADATA_PAYLOAD_BYTES + 1` to pin the open-once capped read.
- Wrap stream-delivery assertions in `tokio::time::timeout` so a lost event fails rather than hangs.
- Bind an ephemeral port once and serve on that listener. Avoid drop-and-rebind readiness races.

### Fixtures and white-box seams

- A same-file `#[cfg(test)] mod tests` can inspect private state; a sibling module cannot.
- Handler tests can use real in-memory stores and call handlers directly without a live gRPC server.
- Pick the immutable-store fixture by behavior: canned response, unconditional failure, or a wrapper
  around a real store that selectively injects one fault. Only the wrapper composes with real state
  serialization and fragment walks.
- Shared mock state must use `Arc`-backed counters/maps so the test and code-under-test observe the
  same clone.
- A migration-owned schema block needs a legacy-non-inheritance pin: assert the sibling store's
  older auto-bootstrap `SCHEMA` const never names the new relations, so an edit can't silently fold
  new DDL into the legacy path. See `lore-postgres/store/immutable_store.rs` (CR-031/WP-118).

### Postgres parameter typing and retry classification

- Symptom: the first mutable-store write returns `SlowDown` forever while Postgres logs no SQL
  error. Cause: a query expression such as `$2::text` makes Postgres expect `TEXT`, but the Rust
  caller binds `i16`; `tokio-postgres` reports a client-side `WrongType` with no `DbError`, which a
  broad no-DB-error retry classifier can mistake for transport failure. What to do: cast through
  the bound SQL type (`$2::smallint::text`), keep any test-side duplicate query identical, and pin
  both layers with `cargo test -p lore-postgres --lib pool::tests -j 4` plus the ignored live test
  `mutable_store_advisory_lock_accepts_smallint_key_type` under `LORE_TEST_PG_URL`.
- Symptom: a query with one placeholder reused across several columns (`VALUES (1, $1, 0, $1, $1,
  $1, ...)`) fails on *every* run against a fresh database with SQLSTATE `42P08` "inconsistent
  types deduced for parameter $1", detail "bigint versus integer" — not a race, not
  environment-specific. Cause: `tokio-postgres`'s extended protocol asks Postgres to infer one type
  per parameter *number* for the whole statement; reusing `$1` against a `bigint` column and an
  `integer` column in the same INSERT gives Postgres two different answers for the same slot, and
  it refuses to unify them. This is a different failure from the `WrongType`/`$2::text` case above:
  that one is a client-side mismatch with no `DbError` at all; this one *is* a `DbError` (planning
  fails before execution), and `err.as_db_error()` carries the full `SqlState`/`detail`. What to
  do: give every logically-independent value its own placeholder number even when the bound Rust
  value is identical for all of them (`$1` for the `bigint` column, `$2` for every `integer`
  column, bound as two separate `&params[]` entries) — don't rely on Postgres widening `integer` up
  to match a `bigint` sibling using the same number. Caught here in
  `PostgresDomainStore::ensure_state_rows`'s `lore_outbox_schema_state` insert (WP-116 Phase 2),
  which reused `$1` across `migration_version bigint` and three `integer` compat-floor columns and
  therefore failed `PostgresDomainStore::connect` unconditionally on a fresh database — reproduce
  directly with `err.as_db_error()` rather than trusting a wrapping error type's `Display`, which
  can collapse a rich `DbError` (code/message/detail) down to a bare `"db error"` string.
- Symptom: a mutation is replayed after connection loss, capacity exhaustion, or server restart.
  Cause: reusing the broad caller-facing PostgreSQL transience classifier as mutation-retry
  authority. What to do: keep mutation retry closed to known-aborted `40001` and `40P01`; treat
  `08`, `53`, `57P01`, `57P03`, and a missing SQLSTATE as requiring operation-specific exact
  readback before any replay. The continuity-client gate pins three total attempts, 25/100 ms
  delays, whole-millisecond `SET LOCAL` statement/lock timeouts on both mutation and authoritative
  read transactions, and the negative SQLSTATE set with
  `cargo test -p lore-object-dispatch --lib -j 4`.
- Symptom: commit-loss recovery returns lookup code `FOUND`, or treats a matching epoch/interval as
  proof of an exact mutation. Cause: replacing the decoded pre-COMMIT result with an incomplete
  read projection. What to do: adopt only when authoritative readback matches every projected
  pre-COMMIT field and return the pre-COMMIT value; incomplete snapshot, epoch, or archive reads may
  prove only safe retry or unresolved ambiguity. Pure readback matrices pin mismatched-winner
  behavior offline. A real socket fault after server COMMIT remains an explicit live contract, not
  something those pure tests claim to execute.
- Symptom: a PostgreSQL TLS fault proxy times out during connection when bound only to
  `127.0.0.1`. Cause: the production retention client correctly requires a DNS host, and Windows may
  resolve `localhost` to `::1` first. What to do: bind the disposable proxy to `localhost`, preserve
  that DNS name in the proxied URL and certificate SAN, and use its selected port. Gate:
  `lore-object-dispatch/tests/run-retention-client-live.ps1`.
- Symptom: a disposable `40001`/`40P01` trigger returns a permission error. Cause: the maintenance
  caller cannot advance the admin-owned nontransactional attempt sequence. What to do: use a
  `SECURITY DEFINER` function with `search_path=pg_catalog`, qualify the sequence, and assert two
  attempts. A lost-COMMIT proxy must ignore earlier pipelined `ParseComplete`/`Z(T)` frames after
  frontend `Q/COMMIT`, drop only after backend `C/COMMIT` plus `Z(I)`, close both socket halves, and
  require its fault-fired signal before claiming reconciliation. Gate CR-029 with
  `lore-postgres/tests/run-domain-maintenance-live.ps1`. The TLS retention proxy additionally pins
  the fixture CA and maintenance CN. Serialize direct runs with a database advisory-lock lease.

### A fanout helper reusing the caller's `LockSequence` must lock earlier classes before the caller's own lock, not after

Symptom: every real-data case of a multi-repository generation bump (CR-031's
`fragment_lifecycle_generation` fanout) returns `DomainError::Internal` ("lock
order violation"); every offline/unit case stayed green because each used a
fragment with zero associations, where the fanout loop is a no-op. Cause: the
helper entered `LockClass::Repository` from inside a transaction whose caller
had already entered a later class (`Fragments`) for its own head lock —
`LockSequence::enter` rejects the downward move. What to do: plan the fanout
(an unlocked, bounded SELECT) before taking any lock in a class later than the
fanout's own; lock the fanout's rows first; take the caller's own later-class
lock; then re-verify the fanout did not grow under that lock, returning
retryable `Contention` if it did. Write at least one live case with a
non-empty fanout — this bug class is invisible to any case whose association
set is empty. `lore-postgres/tests/domain_fragment_lifecycle.rs`'s
`a_readable_to_unreadable_transition_bumps_every_live_associated_repository_atomically`
is that case. The same file proves a *pre-lock* refusal structurally too: call
`sequence.enter(LockClass::Repository)` right after a call that should refuse
before ever entering the later `Fragments` class — success proves Fragments
was never entered, since `enter` rejects exactly that downward re-entry
(`revalidate_push_witness_refuses_over_the_revalidation_limit_before_locking_any_fragment_row`).
For a method borrowing the caller's `Transaction<'_>` instead of owning one
(`revalidate_push_witness`), build an independent connection with
`lore_postgres::pool::build_pool(url, pool_max, &TlsConfig::default())` --
`deadpool-postgres` is a normal (non-dev) dependency, so `deadpool_postgres`
is `use`-able from `tests/*.rs` the same way `tokio_postgres` already is here.

**Reproducing an unlocked-plan-to-locked-head race deterministically needs a row
already IN the fanout to block on, not a test-only injection hook** (a hook
would be a second code path to keep correct). Associate repository R with the
hash beforehand so `lock_lifecycle_fanout` must take its row; hold R locked
externally on a second connection; race the operation under test against a
mutation to a DIFFERENT repository R2 (outside the plan) via `tokio::join!`
(plain `#[tokio::test]` genuinely interleaves two I/O-bound futures, no
`tokio::spawn` needed); let the race commit, THEN release R. Revert-check
against the pre-fix source (`git show <sha>:<path> > <file>`, rerun,
`git checkout -- <file>`) — INV-EF P1-1's case was confirmed RED (silently
`Admitted` instead of refusing) this way.

### Never hash two blocks of program output to rule out a whitespace difference — the pipeline you hashed through may have removed it

Symptom: `domain_migration_parity.rs`'s catalog-parity test failed over five SCHEMA-117
lock-trigger functions that printed as textually identical on both sides of the diff. Cause:
`.gitattributes` pinned `eol=lf` for `lore-object-dispatch/migrations/*.sql` but not
`lore-postgres/migrations/`, so `0001_init.sql` checked out CRLF while the matching Rust DDL
string literal stayed LF. Only function/trigger bodies expose this — tables, columns,
constraints, and indexes are parsed and normalised by the server — so a migration declaring no
functions can be CRLF for years and look fine. The trap: an earlier pass MD5'd both printed
blocks, found them equal, and wrongly ruled out a text difference; the hash was taken
*downstream* of a pipeline (captured output, a redirect, `sed` under MSYS) that had already
normalised the CRs away. Whitespace is the one difference class output-and-hash cannot see. What
to do: query the value's own storage directly, with a query that cannot normalise (here,
`SELECT proname, position(chr(13) in prosrc) FROM pg_proc WHERE ...` returned `1` for all five
functions), or `file <path>` on the inputs; add a `text eol=lf` rule for every `migrations/*.sql`
path. Compare things where they live, never where they were rendered. A `git worktree add`
reproduction is itself a checkout and can manufacture the very CRLF condition under test — it is
not independent confirmation that a failure pre-existed.

### Poisoning a persisted `State`/`Tree` field for a fault-injection test

`State::set_delta_block(hash, count)` is `pub` and the cheapest lever to make a *persisted*
revision's `delta_block()` read fail deterministically: point `hash_delta` at an address
nothing has ever written. Two ordering gotchas, both silent (no compile error, no panic --
the poisoned value just never reaches the store):

- `set_delta_block` calls `tree_readonly()`, which errors on a state whose tree has never been
  loaded. Call `state.tree(repository.clone()).await?` first — on a fresh `State::new()` with a
  zero `hash_tree` this installs an in-memory zeroed tree with no I/O, cheap to call before
  poisoning it.
- `set_delta_block` only sets `TreeFlags::Dirty` on the tree, not `StateFlags::Dirty` on the
  state itself, and `State::serialize` gates entirely on the latter (an early return before the
  tree is ever inspected). Call the public `state.mark_dirty()` too, or the poisoned tree is
  silently never written.

Same shape generalizes: any `set_*` that mutates only the in-memory `Tree`/block runtime cache
needs a companion `mark_dirty()` before `serialize()` will actually persist it.

### Capturing `LoreEvent`s from a real dispatcher in a test

`EventDispatcher::no_dispatch()` (`tests/helper.rs`'s `setup_test_execution`) makes
`send`/`send_error` silent no-ops (`weak_sender: None`) -- fine for tests that don't assert on
events, useless for ones that do. To observe what an operation actually sends: build
`EventDispatcher::new(Some(callback))` with a callback pushing into an `Arc<Mutex<Vec<LoreEvent>>>`
(or just each event's `.discriminant(): u32` if you only need to prove an event kind occurred --
`LoreEvent` does not implement `Debug`, so don't put a whole captured `Vec<LoreEvent>` in a
`{:?}`/`.expect()` message), wrap it in a fresh `ExecutionContext::new_client_with_user_id(...)`,
and scope the whole operation under `LORE_CONTEXT.scope(execution.clone(), ...)`. The forwarder
task drains the channel asynchronously, so after the operation completes, `drop(execution)`
(closing the sender) and poll until `events` contains `LoreEvent::End` -- the terminal event the
forwarder loop (`relay.rs`) sends unconditionally once the channel closes and every buffered item
has been forwarded -- before asserting. **Don't break on "any event arrived"** (an earlier version
of `tests/commit.rs`'s drain loop does this): most `info`/`commit`-style operations send a
non-terminal event first, so breaking on the first arrival can race ahead of a later event you
actually care about -- silently flaky for a positive assertion, and close to vacuous for a negative
one ("no Error event" then only proves the *first* event wasn't one). If you copy that drain
pattern into a new test, drain to `End`, not to first-non-empty.

### Two public callers of one private charset validator need an agreement test, not two isolated rejections

Symptom: a durably-stored id gets rejected forever by a later validation pass, with no way to
clear it. Cause: two public entry points validate the same identity field with different private
helpers (e.g. `lore-object-dispatch/src/request.rs`'s `fingerprint_object_store_request`, whose
output is durably stored, versus `validate_first_seen_prerequisites`, which runs later against
that stored row) — a permissive `validate_canonical_text` at the earlier gate and a strict
`validate_canonical_id` at the later one let an id like one containing `@` pass the first and wedge
behind the second. What to do: when a fix makes an earlier gate re-apply the later gate's charset,
test the *agreement property* directly — for a table of ids spanning the charset boundary, assert
fingerprint-accepts implies first-seen-accepts, and that a rejected id never produces a
`ValidatedRequest` to call first-seen with in the first place (structural proof, not just "the bad
id is rejected somewhere"). A test that only checks the bad id is rejected once would have passed
against the broken code. Gate:
`cargo test -p lore-object-dispatch --test request_fingerprint -j 4 --
fingerprint_and_first_seen_agree_on_the_identity_charset_boundary`.
A crate-private validator reachable only through a folded struct field (here,
`validate_authority_revision`, reachable through `ExpectedRequestAuthority`'s
`protocol_revision`/`policy_revision`/`allocation_revision` via `validate_first_seen_prerequisites`)
needs its bound proven independent of the caller-supplied limit it sits behind: set the caller's
`max_identity_bytes` comfortably above the validator's own byte cap
(`contract::MAX_CANONICAL_ID_BYTES`, 256) so an over-cap value clears the caller limit and is
rejected only by the validator's own check — otherwise the test proves the caller's limit, not the
validator's. The same asymmetry applies to a broader control-character rejection than the shared
`validate_canonical_text` gate provides (which only excludes NUL): use a non-NUL control character
to prove the stricter check is actually reached, not shadowed by the earlier gate agreeing by
coincidence. Gate: `..validate_authority_revision_bounds_are_independent_of_the_caller_limit`.

### A negative control alone doesn't prove the positive path

Two tests that both assert "zero rows / no error event" (a failure case and a genuinely-empty
case) can both stay green under an implementation that emits the error unconditionally and never
runs the success loop at all -- neither one ever exercises a delta/row-producing path for real.
Any error/no-op-shaped regression suite needs a companion positive control built through the
real production pipeline (e.g. `repository::create_local` + `file::stage::stage` + `commit::commit`,
not a hand-poked `State`), asserting the expected non-empty result AND the absence of the error
event. Revert-check it the same way as the negative guards -- narrowing the success gate (or
dropping the loop body) should turn it red while the negative controls stay green, proving it
covers a gap they don't.

**A relative "assert X unchanged" version of this trap (INV-EF P2-11) needs its own check**: before
comparing a value before/after a call, confirm the code path under test can even reach a write to
it -- if it structurally cannot, every implementation passes and the assertion adds nothing; drop
it and keep only a proof that discriminates (`lore-postgres/tests/domain_fragment_lifecycle.rs`'s
`revalidate_push_witness_refuses_over_the_revalidation_limit_before_locking_any_fragment_row` --
`revalidate_push_witness`'s abort arms only `SELECT`, never write `lore_domain_repositories`). A
second shape: two outcomes you mean to distinguish (correctly fenced vs. wrongly proceeded) can
both write the SAME idempotent value to the field you assert on (re-obliterating one epoch always
ends `Tombstoned`/`PURGED` either way) -- assert a field the wrong path would independently
re-derive and thus change, such as a freshly allocated fence, not one both converge on (same
file's `commit_obliterate_fences_a_stale_intent_and_mutates_nothing`, asserting `last_fence`
rather than `state`/`disposition` alone).

### Public multi-path stage concurrency needs a real multi-worker lifecycle test

Parallel nested-sibling stage can report every walker successful while stale ancestor-node writes
make selected files unreachable. A discriminating `lore-revision` regression must call public
`file::stage::stage` on a Tokio multi-thread runtime, deserialize the returned staged hash, verify
every selected path and staged flag, then commit and deserialize the exact commit to compare its
complete file set. Include `force = true` with both committed and staged-add ancestor directories;
current-thread/one-worker runs and event or stage-end counts do not prove topology retention.

### Writing integration tests ahead of an in-flight `src/` contract change

- Symptom: an unscoped `cargo test -p <crate>` starts failing to compile even though you only added
  new `tests/*.rs` files and touched nothing existing. Cause: cargo auto-discovers every top-level
  `tests/*.rs` as its own binary target, so one file written against a stated-but-not-yet-landed
  `src/` contract (a parallel refactor in flight) blocks the whole crate's unscoped `cargo test`, not
  just itself. What to do: scope with `cargo test -p <crate> --test <name>` while the src change is
  still landing -- this builds/runs only that target and lets you keep proving the parts of the
  contract that don't depend on the pending symbols (e.g. `lore-object-dispatch/tests/canonical_id.rs`
  stayed green throughout CR-033's request-state/continuity decoupling because it only exercises
  already-public wrappers). Once the src lands, the exact fn-pointer/struct-field shape of a
  prose-described seam (public vs private fields, `fn(...)` vs closure) is rarely fully specified;
  expect one iteration pass to fix signature mismatches, not a full rewrite -- for CR-033's
  `request_state_wire`/`continuity_wire` split, the only guess that landed wrong was the import path:
  a function can relocate between modules while keeping its crate-root re-export, so import it from
  `lore_object_dispatch::` directly rather than through any module's own path. The two-arg
  `validate_and_encode_object_store_request_receipt`/`..._outcome` demonstrate both halves — they
  moved into `continuity_wire.rs` under Wave 1, then back into `request_state_wire.rs` when that
  module was deleted, absorbing the `_with` variants and dropping the encoder parameter. The
  crate-root path was correct throughout; neither module path was.
- `AuthorizedCallerRegistry` does not derive `PartialEq` (it wraps an `Arc<BTreeMap<..>>` of redacted
  entries). A helper that returns `Result<AuthorizedCallerRegistry, E>` can't be `assert_eq!`'d
  directly; map to `Result<(), E>` first, or compare `.err()` against `Some(..)`.
- `ObjectStorePayloadKindV1`'s two variants are `ObjectStorePayloadKindPutBody` and
  `ObjectStorePayloadKindGetResult` -- not `...ResultPayload`. A minimal state/retention fixture that
  guesses the second name fails at compile time with a "did you mean" pointing at the right one.

### Process-global state

- OTel providers, connection maps, auth caches, and panic hooks are shared by the whole test binary.
  Use unique keys and avoid assertions about global emptiness or size.
- An instrument cached in a `OnceLock` remains bound to the provider active at first construction;
  swapping the provider later does not make an isolated metric test.

### AWS SDK specifics

- Modeled exception builders need explicit `ErrorMetadata.code(...)` to exercise code classifiers.
- Adaptive retry's client rate limiter is not bounded by `RetryConfig::max_backoff` and is shared by
  requests using that client. Keep Standard as the default unless this is re-verified against the
  vendored SDK source.
- `RetryConfig::disabled()` means Standard with one attempt; caller backoff/attempt overrides do not
  apply in Disabled mode.
- Permanent S3 failures need negative assertions proving they are neither missing nor retryable.

### PowerShell live-test runner scripts (Windows)

- Symptom: `cargo test ... -- --ignored --exact <name>` reports `0 tests` / `N filtered out` even
  though the name is correct and the target builds. Cause: a bare comma-separated argument list
  after a backtick line continuation (`` & cmd -- ` ``\n`'--ignored', '--exact', $name`) becomes one
  stringified array *value*, not separate argv tokens -- the native process sees one unrecognized
  blob, silently filters everything out, and still exits 0. Fix: build the list as its own named
  array (`$cargoArgs = @('test', '-p', ..., '--', '--ignored', '--exact', $name)`) and invoke via
  splatting (`& cargo @cargoArgs`). Never trust a runner's "N NOT RUN" as evidence the tests don't
  exist without first confirming an intentionally-broken filter reproduces the same "0 tests" shape
  -- that proves the parser path is reachable, not vacuous.
- `Format-Table -AutoSize | Out-String | Write-Host` truncates columns to the host's reported
  console width, which a non-interactive/redirected `pwsh -File` invocation can report as
  narrower than an interactive terminal -- a results table can silently drop its rightmost
  columns (status/pass/fail counts) with no error. Pin a width: `Out-String -Width 200`.
- A trailing `+` at end-of-line only continues an *expression* (`$x = "a" +`\n`"b"`). A cmdlet in
  command syntax (`Write-Host "a" +`\n`"b"`, `throw "a" +`\n`"b"`) parses `+` and the following
  string as two more positional arguments, not concatenation -- confirmed: the literal `+` and a
  line break land mid-message in the output. Fix: assign the concatenation to a variable first
  (`$message = "a" +`\n`"b"`, which *is* expression context) and pass that variable to the cmdlet.
- Cross-check a runner's hardcoded live-test name/target map against ground truth before trusting
  it: `cargo test -p <crate> -- --ignored --list` needs no infrastructure and enumerates every
  `<name>: test` line under each `Running tests\<target>.rs` header. Diff both directions -- every
  hardcoded entry must appear in the list (catches a rename), and every list entry must appear in
  the hardcoded map (catches an unnoticed new live test) -- treat either direction failing as a
  hard error, not a warning. A `#[cfg(target_os = "linux")]`-gated test is unenumerable (not merely
  filtered) on a non-Linux rig, so a runner must name it NOT RUN from static source knowledge, not
  from this catalog.
- Piping a long-running provisioning script through `head` (or any early-closing consumer, e.g.
  `... | tee log | head -5`) can `SIGPIPE` it mid-run without killing the underlying process tree --
  the foreground shell call returns once the truncating consumer exits, but a detached child (here,
  the `pwsh.exe` driving Docker) can keep running unobserved, still holding a labelled container
  open. Redirect to a file and read it after the process exits instead of piping through a
  line-limiting consumer.
- A container label that merely restates the container's own name (e.g. a `run-id` label derived
  from the same GUID embedded in the name) proves only self-consistency, not ownership -- true for
  *any* correctly running instance of the script, not just the one you happen to be looking at. A
  label-filtered `docker ps` listing never tells you the container is yours or that its creator has
  exited. Before removing a container you did not just create in the current process, get an
  independent ownership signal (e.g. an owning-pid label written at creation time) and confirm that
  pid is dead -- do not infer ownership from "I just ran something and there's a matching container
  now."

### Known tier limitations

- Flat handler fixtures do not run the full commit rollup pipeline, so aggregate tree size can remain
  zero even when per-node sizes are real. Assert aggregate plumbing there and use integration tests
  for the real rollup.
- A local-only fixture may be unable to observe an error after remote fallback normalization. Test
  the integrity consequence as well: whether referenced addresses silently disappear from an `Ok`
  result.
- Runtime-specific I/O backends and real QUIC drain behavior remain platform/live tiers; record the
  omission rather than representing a portable unit run as full coverage.
- **Never source a candidate port from `bind(0)` when the port must be free for BOTH TCP and UDP;
  never "fix" the resulting failure by raising the retry count.** `scripts/test`'s
  `allocate_free_port` (gRPC and QUIC share one number) hard-failed all 20 attempts on Windows with
  `WSAEACCES`/`WinError 10013`, persistently not flakily. Windows keeps SEPARATE per-protocol
  exclusion lists (`netsh interface ipv4 show excludedportrange protocol=udp` vs `protocol=tcp`), so
  a port can be TCP-free and UDP-reserved; measured 2026-08-11, ~1,860 of the 16,384-port dynamic
  range was UDP-excluded in bands of 60-500 consecutive ports, disjoint from the TCP exclusions.
  `bind(0)` hands out ports sequentially from a machine-global cursor (+1/call, measured: 20 binds
  spanned 19 ports), so the retry loop probed 20 ADJACENT numbers -- one band wider than that span
  fails all attempts, and each failure advances the cursor by only 1 (~100 retries to escape a
  100-port band). Fixed by sampling candidates at random from 49152-65535, probing both protocols
  with both sockets held at once. Guard: `scripts/test/test_allocate_free_port.py` asserts the
  candidates are not sequential (revert-checked RED against the old `bind(0)` source: `span 11
  across 12 calls`).

## Appending new findings

Add only lessons likely to recur. Keep each entry short and group it under the closest section.
Chronology, command transcripts, and one-off reviewer narratives belong in `docs/worklogs/`.
