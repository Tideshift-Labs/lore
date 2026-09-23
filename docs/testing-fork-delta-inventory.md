# Fork-delta inventory: `tideshift/main` vs upstream

This is the per-module map from our fork's deltas to their most useful automated gates.
For detailed historical context, gotchas, and design invariants, see the [Appendix](testing-fork-delta-inventory-appendix.md).

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
- **CR-033 cell dispatch authority: continuity family and separate-process service shell removed   [SERVER]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-033-cell-dispatch-authority-continuity-family-and-separate-process-service-shell-removed-server). Gates: `cargo test -p lore-object-dispatch
  --test no_dispatch --test reserve_put --test upload -j 4` `cargo test -p lore-object-dispatch --test terminal_result -j 4` `cargo test -p lore-object-dispatch --test result_ack -j 4` `cargo test -p lore-object-dispatch --test result_discard -j 4` `cargo test -p lore-object-dispatch --test result_disposition -j 4` `cargo test -p lore-object-dispatch --test fetch_lease --test result_disposition --test
  payload_purge -j 4` `cargo test -p lore-object-dispatch --test cell_schema_install` `cargo test -p lore-object-dispatch --test provider_client -j 4` `pwsh -File lore-object-dispatch/tests/run-local-authority-live.ps1` `lore-object-dispatch/tests/run-provider-charge-live.ps1` `lore-object-dispatch/tests/run-budget-pin-refresh-live.ps1`
- **CR-033 charge-admission deadline horizon guard [SERVER]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-033-charge-admission-deadline-horizon-guard-server). Gates: `cargo test -p lore-server --lib -- charge_bound`
- **CR-038 cell schema forward upgrade and spool metadata true-up [SERVER]**: migration 0028 trues
  up a released spool row's metadata charge to its actual retained size (was a flat 16,384-byte
  charge, never given back — the slot-31 wedge); `upgrade_cell_schema` moves an attested R27 cell to
  R28 offline, under the session advisory lock, refusing if any other session is connected (D4) or
  the live catalog is at an unknown/future state. `CellSchemaError::UpgradeRequired`/`FutureSchema`/
  `SchemaOperationBusy`/`ReplicasActive` are new; `DrainClient::verify_schema_revision` is D5's
  write-behind refusal on an unmarked cell. Offline: `cargo test -p lore-object-dispatch --test
  cell_schema_install` (the `forward_steps_carry_no_transaction_control_or_concurrent_index_build`
  case is test-plan item 8: no forward step may contain `BEGIN;`/`COMMIT;`/`CONCURRENTLY`, since the
  installer supplies the one wrapping transaction). Live: `pwsh -File
  lore-object-dispatch/tests/run-cell-schema-forward-upgrade-live.ps1` — its own container (not
  `run-cell-schema-install-live.ps1`'s), because two of its seven cases drive real reservation
  traffic through `drain_reserve_v1`/`drain_cleanup_release_v1`, which need a genuine BLAKE3
  provider at `public.blake3(bytea)` (`local_blake3_v1` refuses without one); the runner builds
  `lorehub/docker/dev-cell/Dockerfile.postgres-blake3` (plpython3u + the `blake3` PyPI package) on
  first use. Eleven live cases: the wedge/upgrade flagship (with its colocated negative control),
  D5's write-behind refusal, catalog-drift/future-marker/replica-active refusals, the advisory
  lock, fresh-install/upgrade manifest parity, three crash points (mid-attest and before-COMMIT via
  a generalized needle-kill proxy that forwards the untagged startup packet before switching to
  tagged-frame parsing; lost-COMMIT via the existing plaintext proxy shape), a backfill/compaction
  race discrimination proof (states 1/2/4 byte-for-byte untouched; a deterministic
  compact-then-reapply-a-stale-snapshot replay of the APPLY step's own guard, real vs the pre-fix
  spool_id-only shape), the release true-up formula plus its underflow-guard discrimination proof,
  and one real-scale case bulk-seeded (SQL) to the exact 8,192-row/134,217,728-byte dev cap. See
  [testing-gotchas.md](testing-gotchas.md#cr-038-forward-upgrade-fixture-gotchas) for the fixture
  traps this tier's synthetic reservation/seeding needed.
  D5's own call path — `FragmentProviderEntry::drain_handles` (`lore-fragment-provider/src/drain.rs`)
  — is pinned separately from `DrainClient::verify_schema_revision` above: two live (`#[ignore]`)
  cases in `lore-fragment-provider/src/tests.rs`
  (`drain_handles_refuses_a_cell_that_predates_the_spool_metadata_true_up`,
  `drain_handles_refuses_a_cell_schema_revision_this_build_does_not_know`) drive `drain_handles`
  itself against a real R27 cell and a planted future marker; a call-site-direct test on
  `verify_schema_revision` does not catch its own call being deleted from `drain_handles`, since
  every offline fixture in that crate already installs the current schema. The disposition arm that
  maps the two schema `DrainError`s to `Internal` (not the generic `DrainAuthority(_) => Transient`)
  is pinned offline in the same file:
  `drain_authority_schema_refusals_classify_as_internal_and_keep_their_operator_message`. A crate
  that needs `cell_schema_install::install_cell_schema_at` (a real R27 fixture) for its own tests
  needs `lore-object-dispatch = { workspace = true, features = ["test_seams"] }` in
  `[dev-dependencies]` — it's `#[cfg(feature = "test_seams")]`-gated upstream in that crate, the
  same shape `lore-transport`/`lore-revision` use their own `test_seams` for.
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
- **Exact-selection commit transaction [CLIENT]**: See [Appendix](testing-fork-delta-inventory-appendix.md#exact-selection-commit-transaction-client). Gates: `cargo test -p lore-revision --test exact_selection_transaction -j 4 -- --test-threads=1` `cargo test -p lore-revision --lib exact_selection::tests -j 4` `cargo test -p lore-revision --lib commit::tests -j 4` `cargo test -p lore --test exact_selection_transaction -j 4 -- --test-threads=1`
- **Upstream revision-tree integration suite [mixed]**: the in-memory suite exercises batch fan-out,
  event ordering, multi-level/mixed-parent batches, concurrency, atomic rejection, and entry fields.
  Gate: `cargo test -p lore-integration-tests revision_tree_test -j 4`.
- **State-block local retention on remote fetch [CLIENT]**: See [Appendix](testing-fork-delta-inventory-appendix.md#state-block-local-retention-on-remote-fetch-client). Gates: `cargo test -p lore-integration-tests --features integration_tests storage_remote_tests -j 4`
- **Tree-block local retention [CLIENT], companion to the entry above**: See [Appendix](testing-fork-delta-inventory-appendix.md#tree-block-local-retention-client-companion-to-the-entry-above). Gates: See Appendix.
- **`revision info --delta`'s delta-read-failure surfacing [CLIENT]**: See [Appendix](testing-fork-delta-inventory-appendix.md#revision-info-delta-s-delta-read-failure-surfacing-client). Gates: `cargo test -p lore-revision --test info -j 4` `cargo test -p lore-storage --lib read::tests::zero_hash_address_short_circuits_to_empty_without_touching_store -j 4`
- **CR-029 domain schema, receipts, outbox-base, backfill, bypass guard [SERVER, WP-116 Phase 2/3]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-029-domain-schema-receipts-outbox-base-backfill-bypass-guard-server-wp-116-phase-2-3). Gates: `cargo test -p lore-postgres --test domain_schema --test domain_receipts --test domain_outbox \
  --test domain_backfill --test domain_migration_parity --test domain_mediated \
  --test domain_bypass --test domain_receipts_lifecycle --test domain_obliterate_fence \
  -- --ignored`
- **CR-029 D2 amendment: platform-ordered completion sequencing [SERVER]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-029-d2-amendment-platform-ordered-completion-sequencing-server). Gates: `cargo test -p lore-postgres -j 1 --test domain_maintenance -- --ignored --test-threads=1`
- **CR-030 lock fencing [SERVER, WP-117]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-030-lock-fencing-server-wp-117). Gates: `cargo test` `cargo test -p lore-server --lib -- is_self_force_unlock_tests`
- **CR-029 WP-116 Phase 4, gRPC metadata carriage, status mapping, and the admission gate   [SERVER]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-029-wp-116-phase-4-grpc-metadata-carriage-status-mapping-and-the-admission-gate-server). Gates: `cargo test -p lore-server --lib grpc::domain_operation_metadata
  grpc::tests::domain_error_mapping_tests domain::tests grpc::handlers::repository_metadata_set
  grpc::repository::v1::repository_metadata_set grpc::handlers::repository_query
  grpc::handlers::branch_list grpc::repository::v1::repository_get`
- **CR-032 superseded-epoch outbox pruning [SERVER, WP-119 Step C/Phase 8]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-032-superseded-epoch-outbox-pruning-server-wp-119-step-c-phase-8). Gates: `cargo test -p lore-postgres --test domain_outbox_prune -- --ignored --test-threads=1` `cargo test -p lore-postgres --lib domain::outbox::prune::tests`
- **CR-032 receiver-side fault-injection seam and live gap/refetch [SERVER, WP-119 Task 3]**:
  `lore-server/src/plugins/remote_notification/faults.rs`, a `DurableStreamSource` decorator behind
  `#[cfg(feature = "failure_generator")]` wrapping the real `GrpcDurableStream`
  (`event_relay/wiring.rs`). Five one-shot anchors read from `LORE_RECEIVER_FAULTS`
  (`receiver.stream.drop`, `receiver.stream.duplicate`, `receiver.stream.poison`,
  `receiver.stream.transient`, `receiver.ack.transient`), triggered by a 1-based ordinal or the
  literal `next`, armed at runtime through `<anchor>.arm` files under `LORE_RECEIVER_FAULT_DIR` and
  answered with `<anchor>.fired`; `LORE_RECEIVER_FAULT_TRACE=1` swaps in a tracing invalidation
  target so an apply/refetch is an artifact rather than an inference. Identity function in a
  default build. This is the receiver-side failpoint the two-process runner's case l (2026-09-15)
  said the crate exposed none of. Exercised by five new live cases (m..q, catalog now a..q) in
  `lore-integration-tests/tests/active_active_two_process_test.rs` via
  `run-active-active-two-process-live.ps1`, against two real `loreserver` processes sharing one
  cell Postgres/MinIO over the real gateway/mTLS/JetStream. Gates:
  `cargo clippy -p lore-server --lib --features failure_generator --no-deps -- -D warnings` (and
  the same without the feature); live: `pwsh -File
  lore-integration-tests/tests/run-active-active-two-process-live.ps1` with `LORE_RECEIVER_FAULTS`
  armed for cases n/o/p/q, `PASS=5 FAIL=0 NOT RUN=0 EXPECTED=5` at last run.
- **WP-114/WP-115 durable promotion send claim [SERVER, `lore-postgres/src/domain/fragments/`]**: See [Appendix](testing-fork-delta-inventory-appendix.md#wp-114-wp-115-durable-promotion-send-claim-server-lore-postgres-src-domain-fragments). Gates: `pwsh -File lore-postgres/tests/run-fragment-lifecycle-live.ps1`
- **WP-114 CD-6/CD-7 write-behind store adapter [SERVER, `lore-postgres/src/store/write_behind/`]**: See [Appendix](testing-fork-delta-inventory-appendix.md#wp-114-cd-6-cd-7-write-behind-store-adapter-server-lore-postgres-src-store-write-behind). Gates: `cargo test -p lore-postgres --test write_behind_stage --test
    write_behind_source_pins`
- **CR-035 write-behind backpressure is not unreadiness [SERVER,   `lore-server/src/fragment_write_behind.rs`]**: See [Appendix](testing-fork-delta-inventory-appendix.md#cr-035-write-behind-backpressure-is-not-unreadiness-server-lore-server-src-fragment-write-behind-rs). Gates: `cargo test -p lore-server --lib fragment_write_behind`
- **WP-122 L5 [SERVER]**: See [Appendix](testing-fork-delta-inventory-appendix.md#wp-122-l5-server). Gates: See Appendix.
- **Pool-acquisition latency instrument [SERVER, `lore-telemetry/src/pool_acquire.rs`]**: checkout-wait
  histogram/tally, distinct from `operation_duration` and the `pool_waiting`/`pool_available` gauges;
  `100.0` and `250.0` are placement-gate thresholds and must stay boundary-inclusive. A cancelled
  `measure()` (deadline elapsed, losing `select!` branch) must still record — via an RAII
  `AcquireGuard` defaulting to `AcquireOutcome::Abandoned` until `settle()`d, recording on `Drop` so a
  `?`-early-return or a dropped future is still measured — because those are the longest waits and
  dropping them silently biases the quantile low exactly when the pool is under pressure. `Abandoned`
  is excluded from the bucket tally/quantile like `Failed`, with its own `abandoned()`/
  `abandoned_max_ms()` on the snapshot. Gate: `cargo test -p lore-telemetry --lib pool_acquire`.
  `lore-telemetry` has no runtime dependency on `lore-base`; the crate's `[dev-dependencies]` carries
  it solely so tests can use `lore_base::lore_spawn!` (the workspace `clippy.toml`, resolved from the
  nearest ancestor since the crate has no `clippy.toml` of its own, forbids raw
  `tokio::spawn`/`JoinSet::spawn` even in tests).
