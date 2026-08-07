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
- **Upstream revision-tree integration suite [mixed]**: the in-memory suite exercises batch fan-out,
  event ordering, multi-level/mixed-parent batches, concurrency, atomic rejection, and entry fields.
  Gate: `cargo test -p lore-integration-tests revision_tree_test -j 4`.

## Durable test patterns and gotchas

### Build and merge hygiene

- A signature change in production code can leave direct handler tests stale. Build test targets
  after a merge, even when production targets compile.
- If an untouched file reports an impossible macro/import/rlib error after alternating Clippy and
  test builds, suspect stale incremental state. Clean only the affected crate before escalating.
- Regenerate protobuf output and `Cargo.lock` from their sources; do not hand-splice generated files.
- Check which `clippy.toml` governs the crate. A crate-local file shadows rather than extends the
  workspace configuration.

### Deterministic async tests

- Use `#[tokio::test(start_paused = true)]` and `tokio::time::advance` for timer-driven behavior.
- Use near-zero retry policies for behavioral tests; keep one explicit real-default test when the
  default delay itself is part of the contract.
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

### Known tier limitations

- Flat handler fixtures do not run the full commit rollup pipeline, so aggregate tree size can remain
  zero even when per-node sizes are real. Assert aggregate plumbing there and use integration tests
  for the real rollup.
- A local-only fixture may be unable to observe an error after remote fallback normalization. Test
  the integrity consequence as well: whether referenced addresses silently disappear from an `Ok`
  result.
- Runtime-specific I/O backends and real QUIC drain behavior remain platform/live tiers; record the
  omission rather than representing a portable unit run as full coverage.

## Appending new findings

Add only lessons likely to recur. Keep each entry short and group it under the closest section.
Chronology, command transcripts, and one-off reviewer narratives belong in `docs/worklogs/`.
