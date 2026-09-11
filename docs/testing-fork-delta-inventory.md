# Fork-delta inventory: `tideshift/main` vs upstream

Split out of [`testing-guide.md`](testing-guide.md) on 2026-09-11 to keep the orientation guide
short; nothing below was edited, only relocated. This is the per-module map from our fork's
deltas to their most useful automated gates, mixing what changed with the testing lesson each
delta produced. Keep it durable, not chronological — chronological execution notes belong in
`docs/worklogs/`.

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
  [SERVER]** (the cell's own PostgreSQL is the one authority; the CR-033 record, not this guide,
  lists which modules and RPCs went). A module simplified rather than deleted, with **zero** prior
  `tests/` coverage of its own, needs fresh test files, not edits — `config.rs`/`metrics.rs` and the
  `authority.rs` fold (new coverage in `tests/request_fingerprint.rs`) are both this shape. Also:
  `ObjectStoreCompactDependencyFloorKind::Continuity`'s wire value `5` is explicitly retained (D5)
  even though its sibling `ContinuityQuarantined`/`ContinuityAdjudicated` variants were removed —
  don't remove that variant chasing the rest of the family out.
  `ContinuityWireLimits`/`RequestStateWireLimits` are one struct behind a `pub type` alias whose
  owning side can invert across waves — a test importing the alias needs a plain rename to the
  surviving type when the aliasing module goes, not a field-by-field rewrite.
  A suite that covers a crate-private helper through whichever public wrapper was convenient breaks
  when that wrapper's module is deleted, even though it never named the module and the helper still
  exists (`tests/canonical_id.rs` on `contract::validate_canonical_id` via
  `auth::AuthorizedCallerRegistry`). Before calling a module deletion's test cleanup done, `grep`
  every symbol it publicly exported across all of `tests/`, not just files named after it, and
  re-point the matrix through a surviving caller with the same private-helper contract rather than
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
  The eleven `local_authority_*` live tests (the retained cell-authority half) have a
  checked-in provisioning harness:
  `lore-object-dispatch/tests/run-local-authority-live.ps1`. Unlike the retention-client live tier,
  these tests use `NoTls` against a `POSTGRES_HOST_AUTH_METHOD=trust` container and plain
  `postgresql://postgres@...` URLs -- no certificates, no `pg_hba.conf`. Ten of the eleven
  self-provision (roles plus their own `include_str!`'d migration subset), so the harness need only
  hand each an empty fresh database. The exception is `local_authority_canonical_codec.rs`'s live
  test: it installs nothing and states its requirement in its own `#[ignore = "..."]` message, so
  the harness must pre-install precisely that pair, not the full chain -- match what a test's calls
  actually touch. The harness also installs the full chain
  once into its own dedicated database as executed proof it installs cleanly, and asserts the
  documented inert state (0002's tables present, 0004-0006's uninstalled procedures absent). Run:
  `pwsh -File lore-object-dispatch/tests/run-local-authority-live.ps1` (add `-KeepOnFailure` to
  leave the labelled container up for debugging). All eleven tests stay `#[ignore]`; the harness
  opts them in explicitly with `--ignored --exact <name>`, it does not un-ignore them, so the
  crate's baseline `cargo test -p lore-object-dispatch` ignored count is unchanged by this run
  (don't hardcode a count here — it drifts; list it fresh with `-- --list --ignored`).
  CD-1's out-of-band installer/attester itself (`lore-object-dispatch/src/cell_schema_install.rs`
  plus `src/bin/cell-schema-install.rs`, a one-shot operator CLI, not a service) has its own
  offline-only suite, `tests/cell_schema_install.rs` — no Postgres, no `#[ignore]`. It re-reads
  `migrations/*.sql` from disk independently of the module's own `include_str!` copies (so a
  frozen-bytes claim is checked against ground truth, not against itself), and pins: the exact
  install set against the on-disk directory, so a future migration must be classified
  installed-or-deferred or the test fails (read its current size from `CELL_INSTALL_SET`, never
  from a number written here — it grows every CD wave); the interleaved install plan; each schema
  layer's install/read_state function names, revisions, and digest against the migration that
  creates them; the `CREATE OR REPLACE FUNCTION` replacement inventory (scanned by text, not
  hand-enumerated, so an unpinned replace and one dropped from the pinned list both fail); and a `local_authority_put_reservation_provisioning.rs`-style "runtime source never
  calls the install entrypoints" guard extended to the new bin target. Gate:
  `cargo test -p lore-object-dispatch --test cell_schema_install`. One test
  (`cell_schema_error_is_a_standard_redacted_error_type`) is a type-level stub pending the real
  `CellSchemaError` variant list, which the module's pinned contract deliberately left open —
  fill in the per-variant `format!("{e}")`/`{e:?}` redaction assertions once the enum lands.
  WP-114 CD-5's provider client (`provider_client.rs`): `AuthorizedProviderAttempt` is
  crate-private-constructed, and a transport reporting `provider_requests_issued != 1` poisons the
  ledger. That bounds what a transport may issue *and admit to*; it does not prove SDK auto-retry is
  off, because an SDK retry happens below the one call and reports one honestly. Disabling it is
  CD-6's construction obligation, and `ProviderRetryPolicy` is only the declaration.
  `record_no_dispatch` refuses after any issued attempt regardless of outcome: generate such state
  matrices by driving the real API, and give a sequencing rule an axis on both sides of the sequence
  (two successive hand-listed versions both missed the ambiguous case). Keep
  `ProviderAttemptLedger::audit`'s call into `compaction`'s `provider_attempt_audit_is_valid` rather
  than restating the algebra. The matrix's pinned state set is a change-detector, not an oracle — it
  is invariant under swapping the decisive/ambiguous arms, so the two tests pinning that mapping
  directly are load-bearing.
  `validate_endpoint_host` accepts a single-label host (`minio`, `localhost`).
  Double pattern: one closure-scripted double per trait, `new` returning `(Self, Rc<Cell<u32>>)`
  (the counter handle must outlive the double once moved into the client); close over an
  `Rc<RefCell<Option<T>>>` in the same closure to capture what it *receives*, not just call counts.
  When the received type is deliberately non-`Clone` (`ProviderChargeRequest`, so nothing can retain
  a chargeable value past the call), copy the asserted fields into your own plain struct instead.
  `ProviderAttemptLedger::new` takes `(provider_boundary_id, logical_request_id) -> Result<Self, _>`
  (no `Default`); `execute` refuses a request naming a different boundary/logical-request with
  `LedgerRequestMismatch`, and `audit_for(logical_request_id)` replaced `audit()` for the same
  reason — one ledger cannot accumulate two requests' attempts. `authorize` is crate-private; its
  public replacement is `validate_attempt`, so a test asserting the `ProviderChargeRequest` an
  authority receives needs the capture-closure pattern above during a real `execute()`, not a direct
  call. Adding an identity field to a type whose `Debug` is `#[derive]`d is how this module's
  redaction regressed once — check for a hand-written impl whenever a type gains an identity string.
  Gate: `cargo test -p lore-object-dispatch --test provider_client -j 4` (no `#[ignore]`).
  WP-114 CD-4's shared limiter (`provider_charge.rs`, migrations 0021/0022) splits its evidence
  across two tiers. `tests/run-provider-charge-live.ps1` (six `#[ignore]`d tests, disposable
  PostgreSQL 16) owns the effect claims: fusing the debit into the check loop, so a class-cap
  refusal leaves the shared bucket debited, fails
  `..._last_unit_charges_are_atomic_and_fail_closed` at "shared debit must roll back"
  (revert-checked). It does NOT own the locking claims — deleting both the per-boundary
  `pg_advisory_xact_lock` and the check loop's `FOR UPDATE OF state` leaves all six green, since
  SERIALIZABLE plus the harness's own `40001` retry still delivers the outcome. Only
  `provider_charge_schema.rs`'s `charge_locks_and_checks_every_cap_before_inserting_or_debiting`
  (source order lock < grant insert < debit) catches that, so it is load-bearing, not a redundant
  change-detector. `concurrent_charges` is `tokio::join!` over two connections with no barrier, so
  every assertion also holds sequentially: it proves the rollback, not the race. Open gap: nothing
  exercises the function's refusal of a non-serializable caller.
  Comparing a crate's counts across two commits needs `--no-fail-fast`; the default stops at the
  first failing target and tallies only what it reached (19 of 47 here), a plausible-looking count.
- **CR-033 charge-admission deadline horizon guard [SERVER]**: `admit_operation`
  (`lore-fragment-provider/src/lib.rs`, the gateway method, not `FragmentProviderEntry`'s
  forwarder) shifts a queued attempt's `deadline_unix_ms` forward by the time actually spent
  waiting for a charge slot, because callers (`lore-postgres`) mint that deadline from
  `now + io_timeout` *before* the wait. But the governed client's own deadline horizon
  (`PROVIDER_ATTEMPT_DEADLINE_HORIZON_MS`, `lore-object-dispatch/src/provider_client.rs`, 300_000ms)
  is anchored to the attempt id's timestamp, minted before the wait too — so a wait deep enough to
  push the shifted deadline past that horizon fails hard (`Internal`) instead of admitting late.
  `lore-server/src/plugins/postgres.rs`'s `validate_fragment_charge_bound` closes this at config
  time: refuses any `fragment_charge_admission_wait_millis + object_store.timeout_millis` (0 when
  `object_store` is absent) exceeding `FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS` (a re-export of
  the horizon), naming both keys in the error. Pinned at the config boundary only — driving a real
  `admit_operation` queue against the horizon needs `lore-object-dispatch` internals
  `lore-postgres` deliberately can't name (see this file's crate-layout doc), so proving "a shift
  can never land outside the horizon under a *validated* config" end-to-end is not cheaply
  expressible from `lore-server`'s or `lore-postgres`'s own test tiers; not attempted here.
  Gate: `cargo test -p lore-server --lib -- charge_bound` (also runs the pre-existing
  impossible/valid/default charge-bound cases in the same file; libtest's filter is one substring,
  not a name list).
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
  **A scope-key/receipt-key disagreement can be a carriage gap, not a derivation gap — verify which
  before framing a pin.** WP-116: `scope_key_mediated` and `scope_key_mediated_namespace`
  (`domain_operation_metadata.rs`) are byte-identical for the same (org, principal) pair, and
  `GovernedScope::Mediated` (`domain.rs`) already calls the former — an agreeing derivation exists. The
  real blocker is that no governed handler can obtain `org_uuid`/principal identity at all — there are
  TWO carriage sites, and only one is compile-time pinned (a no-`..`-rest-pattern exhaustive destructure
  over the three-header struct, so an added field forces revisiting the pin). The second site,
  `AuthorizationToken` (`auth/jwt.rs`), is deliberately left unpinned by that technique since it mirrors
  an upstream JWT contract and would churn on every refresh — check it by hand when closing MISSING-1.
  Cross-family scope-key inequality
  (`repository-*-v1\0` vs `mediated-v1\0`) and cross-namespace consume failing closed
  (`ADMISSION_REJECTED_V1`, no mutation, source row stays `PREPARED`) are PERMANENT invariants, true
  whether or not the carriage gap ever closes — they must stay green forever; add a positive proof
  alongside once carriage lands, never replace them. Tests: `domain_operation_metadata.rs`'s
  `direct_and_mediated_scope_key_families_never_collide` /
  `mediated_scope_key_derivation_already_agrees_with_the_prepare_side` /
  `domain_operation_metadata_carries_no_org_or_principal_identity`; `domain.rs`'s
  `a_mediated_prepare_key_cannot_be_consumed_by_a_repository_scoped_governed_mutation` (tracked in
  `run-domain-enforcement-live.ps1`).
  **A generic gate's own unit tests don't prove one call site's legacy path is reachable.** Check each
  fenced handler individually for a `handler(domain_context: None, ...)` call asserting the pre-gate
  outcome before assuming coverage exists.

