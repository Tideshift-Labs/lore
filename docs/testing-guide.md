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
