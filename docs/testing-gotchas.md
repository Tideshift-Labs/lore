# Durable test patterns and gotchas: `tideshift/main`

Durable, recurring testing lessons grouped by topic.

## Build and merge hygiene

- **Rebuild test targets after merge**: Signature changes might not break `cargo build` but can break `cargo test`.
- **Incremental state issues**: If untouched files report impossible errors, clean the affected crate.
- **Timing-sensitive tests**: Rerun failures in isolation; they might be scheduling flakes under load.
- **Protobufs**: Regenerate instead of hand-splicing. Box large `prost` oneofs to avoid large enum variants and pin the boxed shapes.
- **Clippy**: Check crate-local `clippy.toml` which shadows workspace configs.
- **A restored file can still test red** (stale binary): after a mutation-probe restore cargo can reuse the mutated build, with no `Compiling <crate>` line, only `Finished`. Causes: heavy concurrent `cargo` in a shared `target/`, or a byte-identical restore that carries an OLDER mtime (`Copy-Item`; `lore-server`, WP-120). Restore by writing the bytes back, then touch the file (`(Get-Item $f).LastWriteTime = Get-Date`) or `cargo clean -p <crate>`, and confirm a `Compiling <crate>` line before trusting a result.

- **`LNK1140: limit exceeded for program database`** linking `lore-transport`'s `--test unit` on
  Windows: the debug PDB is too big. Not a code fault. Build with `CARGO_PROFILE_DEV_DEBUG=0` and a
  separate `CARGO_TARGET_DIR` (changing the profile env invalidates the shared target cache).
- **`lore-storage` write tests share the process-global `STORE_IN_FLIGHT`** (`write.rs`), keyed by
  `(partition, address)`. Two concurrent tests storing the same address make one "inherit" the
  other's placement, so counts such as Puts reaching a fake come out low and flaky. Give each test
  its own seed range. A real `StorageSession` over a scripted `Storage` needs no private
  constructor: `connection::add(scheme, EnvironmentOnlyProtocol)` + `connect` +
  `StorageConnector::new(vec![fake]).session_pool(..).pick()` (pattern: `tests/unit/write/unmanaged_gate.rs`,
  after `lore-transport/tests/unit/session_pool.rs`). Needs `lore-transport` `test-util` as a dev-dep for
  `VolatileAttemptStore` (managed scope).
- **Counting server-side refusals in `lore-integration-tests`**: the QUIC stream handler runs on the
  net runtime's threads, so a thread-local `tracing` subscriber sees none of its events. Install a
  process-global layer once and attribute each `handler_error_label = "UnsupportedClient"` event by
  `LORE_CONTEXT.try_with(Arc::as_ptr)` of the emitting task (tests in one binary run concurrently).
  See `quic_strict_admission_test.rs` (`count_refusals_for`). Measured on a strict cell, 64 tracker
  writes: 64 refusals without the unmanaged-write latch; with it, 1 when the refusal is learned first (deterministic). Dispatched all at once the count varies with scheduling (observed 19-64 for 64 fragments).

## Live lock fixture (`lore-revision/src/live_fixture.rs`)

- **`Log` events never reach a test callback** (`lore_warn!` text, e.g. the force-release listing):
  `lore::log::initialize()` is what routes `lore_log_dispatch` into the execution context. Call it
  in the test's capture helper (idempotent). Without it the captured log list is silently empty.
- **Who is "the caller"**: `execution_context().user_id()` comes from the repository config
  `identity`. `LiveRepository::create` sets none (empty caller); use
  `create_with_files_and_identity(url, names, "fixture-user")` to choose one.
- **The stub `Query` filters by requested owner and records it in `LockCall.owner`**; set
  `LockPolicy.query_ignores_owner` to model a server that ignores the filter. Tests of
  no-paths `--force` release: `lore/tests/release_owner_scope.rs`.

- **Two identities / another user's lock without a real server**: caller = repo config identity
  (`create_with_files_and_identity`), holder = an owner string in `LockServer::set_status_locks`
  (the stub's `Status` answer; `Query` has `query_result`). Recipe: `lore/tests/lock_refusal.rs`,
  `lore-revision/tests/unit/lock/file/held.rs`. The stub has no storage service, so a commit's
  upload is best effort (commit still lands) but a push past the check fails with -1: assert
  "status != 45" and the server's call log, not push success. `BranchAnswer::NotFound` makes
  `push_change_paths` return `Err` (lookup error); a zero `latest` gives `Ok(None)`.
- **Hang in a live-fixture test that stages**: `load_and_connect(.., ReadWrite)` already holds the
  per-path write token, so a second `RepositoryWriteToken::acquire` deadlocks. Acquire once, then
  `load_and_connect_with_token(.., Some(token.share()))`, stage with `&token`, and `flush(true)` before
  reading the staged anchor from another context.

## Deterministic async tests

- **Time pausing**: `#[tokio::test(start_paused = true)]` doesn't work well with cross-thread I/O (`lore_io::IoDriver`) or tasks spawned on the global `lore_base::runtime::runtime()`. Use unpaused clocks with real margins for these.
- **Zero-retry policies**: Use near-zero retries for behavioral tests to avoid artificial delays.
- **Lifecycle callbacks**: Use `FileStageEnd` to remove an Add; use `FragmentWrite` to mutate working bytes to ensure immutable capture behavior.
- **Rejections**: Follow rejected exact-selection attempts with sequential-retry cases to ensure no stale metadata is left in memory.
- **UTF-8 limits**: Test exact byte boundaries and one byte over. Include sparse binary sources to test open-once read caps.
- **Timeouts**: Wrap stream assertions in `tokio::time::timeout`. Bind ephemeral ports once to avoid readiness races.
- **Timing assertions on a real clock**: when pinning "at least the sleep duration" (e.g. a
  timer/`measure`-style wrapper), assert a lower bound only, with margin (e.g. sleep 100ms, assert
  `>= 90.0`) — never an upper bound tight enough to flake under scheduler load. `start_paused = true`
  makes `tokio::time::sleep` resolve without any wall-clock wait, which would make the assertion
  trivially true regardless of whether the wrapper timed anything; use a real, unpaused clock instead.
  See `lore-telemetry/src/pool_acquire.rs`'s `measure_records_the_actual_wait_not_a_zero_duration`.
- **In-process race with a `pause` failpoint**: symptom: a second race case in the same test process
  never pauses. Cause: `LORE_FRAGMENT_FAILPOINTS`/`_DIR` are read once per process. Do: one case per
  process (`--exact`), the runner supplies both env vars per case, the test asserts them (no silent
  skip), arms `<anchor>.hold` BEFORE starting the operation, and drives the race inside
  `tokio::join!(operation, async { wait .reached; race; remove .hold })` (no spawn needed; the
  paused GET holds no DB resource). Reference: `lore-postgres/src/store/fragment_write_behind_staged_read_tests.rs`.
- **Hang regressions over h2 (`lore-transport`)**: symptom: a tonic server cannot reproduce a
  proxy-only hang. Cause: tonic closes the request body with its trailers-only refusal; a front
  that keeps the body open does not. Do: a raw `h2::server` (dev-dep) that answers trailers-only
  and keeps draining the body, plus a per-call `tokio::time::timeout` that panics, so a hang is a
  named failure. Reference: `lore-transport/tests/unit/grpc/storage_client/stream_deadline_tests.rs`.
  Seam: `StorageService::with_stream_idle_timeout` (feature `test-util`).
- **tonic `connect_timeout` is not a handshake bound**: a peer that accepts TCP and never speaks h2
  still returns from `Endpoint::connect()`; only the per-RPC `timeout` ends the call (30 s on the
  auth channel, measured). Those two tests are `#[ignore]` (real 30 s): run with `-- --ignored`.

## Fixtures and white-box seams

- **One refusal across several transports (`lore-server`)**: table-drive it through a small
  `Transport` trait (`store`/`cas`/`assert_refusal`) over a counting `MutableStore` wrapper plus a
  pre-seeded read-back, so each case proves both the wire answer and no store effect; add a positive
  control per transport. Services are built with their public constructors (`LoreStorageService` for
  v0+v1 gRPC, `StorageService`/`StorageServiceV4` with `Arc::new(None)` verifier = auth off). Worked
  example: `lore-server/tests/unit/domain_key_refusal.rs`.
- **HTTP in-flight/drain through the real `create_router`**: `ServerHealth::new_without_availability`
  then set `health.drain`; drive with `tower::ServiceExt::oneshot` (not `TestServer`) and a
  `Body::from_stream(ReceiverStream)` so the PUT blocks on its body while you read
  `DrainState::active_rpc_requests()`. `CoreHopLayer` spawns on call, so use
  `flavor = "multi_thread"` and poll the counter with a deadline. See
  `lore-server/tests/unit/http/content_upload_drain.rs`.
- **Source-pin ordering inside `async_main`**: strip `//` lines, then compare byte offsets of the
  call, the last `configure_domain_context(`, and each `launch_*_server(`; assert the call text ends
  `)?` and names its input. A block comment would still pass a text pin, so mutation-probe by deleting the
  statement, not commenting it. `lore-server/tests/unit/domain/require_domain_enforcement.rs`.
- **`lore-integration-tests` remote mutable cases use `KeyType::Untyped`**: the server refuses
  domain-owned key types on the generic mutable RPCs. `storage_mutable_test.rs` is local-handle only
  and unaffected. Run: `cargo test -j 4 -p lore-integration-tests --features integration_tests --test
  integration -- storage_remote_test` (in-process servers, no compose; first build ~6 min).

- **Identity preservation**: Versioned derivations must preserve old identities. Test V2 successors against explicit V1 predecessors.
- **Testing scope**: Same-file `#[cfg(test)] mod tests` can inspect private state, sibling modules cannot.
- **Immutable-store fixtures**: Use behavior-based fixtures (canned responses, selective fault injection).
- **Mock state**: Use `Arc`-backed counters/maps for shared observation.
- **Thin wrappers**: Test wrappers directly to catch dropped/delegated arguments.
- **Cross-repo fixtures**: For paths like `../../lorehub/...`, skip gracefully if the sibling repo is absent, but panic if the path is explicitly requested but missing.
- **Asserting "this path took no pool checkout"**: `Pool::checkout_sites()` keys by source
  `file:line`, not by name. Find the line at test time (`include_str!` the source, locate
  `async fn <name>(`, take the first `self.checkout()` after it, assert exactly one header match) and
  compare before/after deltas. Always add a positive control that the same probe sees the leased/slow
  path take exactly one, or a stale line reads as a passing "zero".
- **Exercising the real `exchange()` through `lore_transport::connect`** (recipe:
  `lore-transport/tests/query_scoped_exchange.rs`): a fake EnvironmentService advertises
  `auth_url = "<unique-scheme>://..."`; register a stub `Authentication` under that scheme
  (`authentication::add`, process-global, so one scheme + identity + repo ids per test). Supplied
  `identity_token` skips the token store but must be an unsigned JWT with `sub == identity` and
  `aud` containing `127.0.0.1`, as must any token the stub returns. Connect with
  `RepositoryId::default()` so the connect-time exchange does not fire. `cache()` is `test_pub`;
  clear by `tokens.lock().retain(|k, _| k.1 != identity)`, not `clear_authz_cache()` (global).
- **Attempt-journal scan vs marker hit** (`lore-revision/tests/admission_marker.rs`): the
  `phase_diagnostics::Probe` `child_parse` delta is the discriminator (a full scan parses every child
  on disk; a hit parses only pending). Install the probe and publication probe on
  `std::fs::canonicalize(tempdir)`: the repository fence canonicalizes (`\\?\` on Windows) and probes
  match by `starts_with`, so a plain tempdir path silently counts zero. To isolate one fingerprint
  input, edit the root JSON (keeping `validated`) or the child file directly. Existing-file `child_read`
  counts double (pending and settled paths both read), so assert on parses. `finish_parent` now
  records the marker (and prunes settled children older than 7 days; `tests/attempt_prune.rs`), so a
  fixture that needs an "unseen" journal strips `validated` from the root (`completed_unmarked`).
  Age children with `File::set_modified`; age parents via `Uuid::new_v7(Timestamp::from_unix(NoContext, ..))`.
  `begin_parent` refuses a second open parent, so build an incomplete one by editing `complete` in
  the root. `cargo clippy -p lore-revision --all-features` fails on `lore-storage`'s `oodle`
  (`OODLE_LIB_DIR not set`); list the other features explicitly.
- **A regression test must be forced red**: a regression test can pass without the fix (vacuous: it never reaches the broken path). Before trusting one, remove or mutate the fix and watch the test fail, then restore (freshness rule above). `a_repeat_finish_on_the_same_instance_does_not_trust_an_evicted_damaged_child` (`tests/attempt_prune.rs`, `0816351d`) was shown red without the cache eviction and green with it. Two corollaries: a test that disables the production bound (slot limit, cap, throttle) to reach the fault measures a configuration we do not ship, so keep the shipped bound on and drive the fault another way; and if red and green fail at the same rate, the test cannot discriminate (seen on the Put in-flight regression, `6dc5bad2`).
- **Fault injection**: Inject faults by key identity rather than call ordinal. Stand in for real-process conditions by calling production write paths directly to ensure real fences are exercised.
- **Closed metric-label sets**: pin the exact literal list in `ALL` order, then pin the real call
  sites, not just a hand-written table. For SQL-keyed labels (`drain_procedure_label`),
  `include_str!` the client sources, cut at `#[cfg(test)]`, and assert every `"SELECT ...
  object_store_retention."` literal maps to a specific label, so a `_v3` rename cannot fall into the
  catch-all bucket. A `tokio_postgres::Error` is unconstructible in a unit test; test the pure
  `code`/`message` functions and pin the shared message literal by source scan. A test-only
  `match` over a cause enum trips clippy `match_same_arms` if two arms share a body: merge them.
- **Real clone against an in-process server** (`storage_remote_test.rs`,
  `clone_with_delta_block_fault`): `lore::repository::create` with `<server.url>/<name>`, stage,
  commit (a plain commit names a non-zero `tree.hash_delta`), `branch::push`, then wrap the served
  store with a fault set AFTER the push. Run it as `--test integration <name>` (one binary, not
  `--test storage_remote_test`). `server.shutdown().await` after a clone panics (the clone's pooled
  connection keeps the listener up): `drop(server)` and read the clone with an `offline: 1`
  `ExecutionContext` + `load_and_connect(path, ReadOnly)` instead. A full `remote_get_retry` pass
  on SlowDown is 61 gets and ~55 s wall (50 ms to 1 s backoff, 60 attempts), so a "outlasts one
  pass" test costs about a minute.
- **Governed handler without Postgres**: carried admission (`carriage(true)` headers + a `lorehub-control-plane` service-account token) is a pure projection, so `RepositoryCreateScriptedStore` / `ScriptedDomainStore` serve the whole delete or v1-create handler. To prove its follow-ups survive a dropped request, use a `NotificationSender` that signals `entered`, awaits a `Notify`, then bumps `finished`; `select!` the handler against `entered`, drop it, release, wait for a post hook, assert `finished == 1` (`p12_tests.rs`, `a_dropped_governed_branch_*`).
- **Race between a push's name check and its publish**: `PausedStore` (`membership_tests/paused_store.rs`) pauses at `branch_push_commit`, after the check. Move `lore_domain_repositories.default_branch_id` first (a delete refuses the default), then commit a real `branch_delete` or a SQL generation bump. A tombstone answers `TOMBSTONED_V1` (`NOT_FOUND`) before the generation compare; only a bump reaches `CAS_MISMATCH_V1` (`ABORTED`).
- **Feature-gated test files rot silently**: `grpc_mutation_dispatch_loss_test.rs` and `replication_service_test.rs` need `--features grpc_integration_tests`; a default-feature filter reads "0 passed" and hides an API change (`lore_transport::connect` gained `AuthMode`). Build with it after a transport merge.
- **Live QUIC server-side probes** (`quic_declared_session_test.rs`): symptom, a client-side count
  stands in for what the server holds. Cause, `StorageServiceV4.session_map` is private. Do: add
  `features = ["test-util"]` to `lore-server` in `lore-integration-tests` dev-deps, wrap the service
  in a `QuicService` that records `(cmd, session_id, Authorize action byte)` in `parse_request_bytes`
  and pushes `inner.session_map.clone()` per accepted connection, then read `map.entries.len()` and
  `map.get(id)`. A stock-server stand-in is a `MessageParseError::ParseFailure` for Authorize action 2
  (answered status 1); `MessageHandleError::UnsupportedClient` is status 200. `connection.session()`
  starts the undeclared session eagerly, so snapshot the wire before asserting "no action 0". To
  observe a drop-time `session_stop`, `drop(session)` and `connection.release_session(..)` (the pool
  pins it). `#[tokio::test]` is current-thread: do not `block_in_place` inside a fixture.
  `async_yields_async` clippy fires on `lore_spawn!` as an async block's tail: `.await` it inside.

- **Stalling a QUIC client write on purpose (`lore-transport/tests/unit/quic/scripted_storage_peer.rs`)**: symptom, a send-bound test cannot make `write_chunks` accept zero or partial bytes. Cause: credit comes from the peer's per-stream receive window, refreshed only after it reads `WINDOW/8` on that stream. Do: raw quinn peer with a small `stream_receive_window`, read headers always but gate payload reads; keep bytes read before the gate under `WINDOW/8`, then credit left = `WINDOW` - bytes the peer counted on that stream. Fill it exactly with a `Reply::EarlyOk` write (answered from the header) to get a zero-byte stall with a free lock. A sequential caller sits on stream 2 once all 8 streams exist (9 round trips); to queue behind a stalled writer, hold one read on each of streams 2..7, answer the stream-2 one, then start the writer. A trickle (`throttle`) gives a lock holder that keeps writing. `VolatileAttemptStore` refuses `record_managed`; wrap it in a journal that overrides it.
- **Testing the managed wait scope (`lore-revision/tests/managed_remote_scope.rs`, `managed_workflow_scope.rs`, `lore-transport/tests/unit/quic/managed_wait_scope.rs`, `lore-integration-tests/tests/quic_managed_push_hang_test.rs`)**: symptom, a spawned connect/session-start/Query reconnect has no managed deadline (a spawn drops task-locals), and a test that only waits on it hangs for minutes. Do: give every such test a hang guard (20-40 s) so a missing deadline fails red; assert the spawned task sees `has_managed_caller() == false` but `in_managed_wait_scope() == true`; prove "no total-time cap" with a sequence on a LIVE peer longer than the bound. A mid-push QUIC fault needs the real order (push #1 over QUIC, second commit, close the QUIC server, black-hole the UDP port) in a separate binary that sets `LORE_QUIC_MANAGED_IDLE_TIMEOUT` from a `ctor`; in `lore-revision` a `LiveRepository`/`LockServer` test panics ("task-local ... without setting it first") at drop time too, so wrap the WHOLE body in `LORE_CONTEXT.scope(fixture_execution_context(), Box::pin(body()))`. `LiveRepository::create` (no identity) makes `load_and_connect` run a BLOCKING connect; use `create_managed`. A server that closed the connection is only noticed on first send, so that first command counts as dispatched and its expiry is NOT the not-sent marker. A UDP black hole needs no live front: a bound `std::net::UdpSocket` that never reads (no ICMP) makes `connect` fail `Disconnected` after the fixed 5 s handshake (`unreachable_handshake.rs`). A fresh-connection commit needs `connection::remove_connection` on the cached one first (`forget_cached_connection`); the first upload fails at once on settled storage readiness, so the clock bounds the command (one 5 s handshake, not two) but cannot show how the uploads ended. A handshake the server answers and fails (untrusted cert on `lores://`) fails fast and gets the no-firewall message. Mutant check: edit a COPY of the tree (robocopy minus `.git`/`.venv`/`target`) with an isolated `CARGO_TARGET_DIR`.
- **Live `lores://` (TLS) and lost-answer cases (`lore-integration-tests/tests/quic_lores_tls_test.rs`, `quic_managed_write_proof_test.rs`, shared fixture `quic_managed_write_support/`)**: symptom, no CA knob for the storage clients (`custom_ca: None`, `quic/storage_service/auth.rs`). Cause: `lores`/`grpcs` validate against webpki roots plus `rustls-native-certs`, which uses ONLY `SSL_CERT_FILE` when set, on Windows too. Do: rcgen CA + leaf with IP SAN `127.0.0.1` (not CA-flagged), TLS on BOTH legs (gRPC resolves the environment), and set `SSL_CERT_FILE` from a `#[ctor::ctor]` in a DEDICATED `[[test]]` binary (process-wide; a write from a test thread races C `getenv`). The connect error is a bare `Disconnected`: assert the cause from `lore_base::log::set_log_callback` + `LoreLogLevel::Debug` ("Failed QUIC connecting ... certificate"), and that `probe.wire()` stayed empty. A lost answer is deterministic: hold the first applied `Put` in `run_request_handler`, close the server, and bring the REPLACEMENT up before the writer returns (`lose_answer_and_restart`); a closed server's wire cannot show a resend. To reach the session layer's `replaced == true` path, call `Connection::advance_storage_generation_before_epoch_for_test()` while the answer is owed (mutation `not_dispatched || true` at `session.rs:468` is red only there). `declared_session_count()` on the scope is the client-side proof of a declared QUIC session (0 on gRPC). A session start must bind its id to the generation its `Authorize` was FRAMED on (`Storage::session_start_bound` / `session_start_declared` return it), never one sampled before the call: after a reconnect the first managed call makes exactly ONE declared start (wire + `Probe::declared_live()` back to 0 after the scope). Replace the server mid-test with `replace_server(&mut cell)` and call `connection.ensure_storage_connected()` first or no reconnect is exercised. Unit proof without infra: `lore-transport/tests/unit/quic/session_start_bound.rs` (scripted peer `close_connections` + `Reply::DisconnectThenOk`) and the two `*_reconnect_*` cases in `lore-transport/tests/managed_session_attempt.rs` (those alone catch a `SessionBinding::resolve` or `session_pool` pre-sample; a second write in the same scope is what exposes a stale binding).
- **Scripted-peer unmanaged-reconnect repro (`unmanaged_reconnect_bound.rs`)**: `client.get` fails `get: Invalid server response` (default answer is an empty body); use `client.query(session, &[addr])` with `peer.rule(Command::Query as u8, Reply::Ok(vec![0]))`. Black-hole the port: `peer.stop()`, wait `closed == accepted`, `drop(peer)`, retry-bind a `std::net::UdpSocket` (no ICMP: handshakes time out at 5 s); revive with `Peer::start_on(port)` retried the same way. Red at HEAD is the outer timeout (stock loop ~3.5 min).
- **A LIVE peer that stalls the reconnect (`reconnect_stall.rs`)**: `peer.set_new_connection_limits(max_bidi, window)` (`Endpoint::set_server_config`, new connections only) then `peer.close_connections()`: `max_bidi` 0 hangs `open_bi`; `(16, 1)` plus `peer.stop_first_stream_of_new_connections(true)` stops stream 0 while its send half stays parked open, so the replacement's reader never ends and pass 2's drain hangs (window must be nonzero-but-tiny: the first frame has to open the stream at the peer). Assert `stopped_streams() >= 1` and `accepted_connections() >= 3` before the hang verdict. Pins in `unmanaged_reconnect_pins.rs`: `classify` called on a real `StorageClient` after a real give-up (`given_up()` is private); an opt-out client is a delegating `ServiceClient` wrapper with `bounds_unmanaged_reconnect() == false` driven through `send_with_reconnect` with session 0 (a pre-reconnect session id is refused after the swap).
- **Unmanaged silence bound (`bound_unmanaged_silence`, `lore-transport/tests/unit/quic/silence_bound.rs`)**: the process switch is one-way, so the unit binary never calls it; opt in per connection with `quic().set_silence_bound_for_test(Some(true))` plus a short `set_managed_idle_for_test`. A slow-but-moving answer is `Reply::Trickle { body, piece, every }` (answer frame in pieces; only a trickle of at least 3 bounds shows the bound follows `last_recv`, not the send). Live proof is `quic_unmanaged_silence_sync_test.rs` (own binary, switch called at test start): arm `hold.hold_all` AFTER setup with `hold.armed` false and a 600 s `grace`. A remote read the bound ended must map to `Disconnected` (`lore-storage` `read_error_to_storage`): as `NotConnected` the read retried on a fresh session five times, a full bound each (6 Gets, -1, about 25 s at a 4 s bound); now 1 Get, ffi 28, one bound.
- **Environment-red tests on this Windows rig, not yours**: `lore-base --test heap_reap` `idle_heaps_are_reaped` fails after a 30 s wait on a pristine HEAD rebuild too (passes on some builds; flaky); `lore-revision --test unit` `fs::walk::a_faithful_copy_keeps_streams_security_attributes_and_sparse_ranges` fails on an ACL `AI` flag difference. Confirm with a throwaway `git worktree` of HEAD and a separate `CARGO_TARGET_DIR` before blaming a change.
- **Choosing a JWT `exp` in a client or live test (WP-124 5b)**: symptom, a test needs a session token of a known age
  with no auth service. Cause: a supplied access token is returned by `exchange` unchanged (a non-empty `auth_url` is
  only needed so the client calls it), and `lore_credential::user_info_from_token` reads `exp` from an unsigned JWT
  (`iss`, `sub`, `exp`, `aud`). Do: `StorageClient::connect(.., auth_url = "x://y", .., &SuppliedCredentials::new("", jwt))`,
  or `lore_transport::connect(url, <unique identity>, repo, 1, "", jwt)` against a fake `EnvironmentService`
  advertising an `auth_url`. Rotate later with a second `connect` for the same url+identity (same `Arc<Connection>`).
  A real `JwtVerifier` keeps jsonwebtoken's 60 s leeway, so a live token already 45 s old still starts a session and
  the server refuses it ~15 s later (`quic_token_expiry_test.rs`). The client rebinds on its own clock at `exp`, 60 s
  before the server refuses, so a fixed token never makes a live `StorageSession` see a 201; use the raw
  `connection.storage()` handle for the server-side refusal. `Reply::StatusThenOk{status,times,body}` and
  `Reply::HoldStatus(status)` on the scripted peer script the 201 cases.
- **A test-only extra `Reply` variant used by only one including binary trips `dead_code`**: the scripted peer is
  compiled in the unit binary and (by `#[path]`) in `tests/*.rs`; a variant used by just one fails clippy `-D warnings`
  in the other. Use each variant in the unit binary too, or cover it there with one small case.
- **PowerShell double-quoted strings eat backticks in doc comments**: a `Replace("..`times`..")` wrote a TAB and a
  backspace into a `///` line (clippy: "using tabs in doc comments"). Edit source lines with the Edit tool, or use
  single-quoted here-strings.
## Postgres & Database Testing

- **250ms DDL limit**: `lore-postgres` bootstrap DDL has a 250ms limit; it can fail on a loaded host. Wait and retry rather than debugging a fresh container.
- **Parameter typing**:
  - Client-side `WrongType`: Cast bound SQL types explicitly (e.g. `$2::smallint::text`).
  - `42P08` inconsistent types: Do not reuse placeholders (`$1`) for different column types even if the Rust value is the same. Use unique placeholders (`$1`, `$2`).
- **Retry classification**: Retries should not be triggered by broad transience classifiers for `40001`/`40P01`.
- **Locking order**: Fanout helpers using `LockSequence` must lock earlier classes *before* the caller's lock, not after.
- **Measuring `numbackends` on a connection you then drop races itself.** Symptom: a test
  proving a Postgres-connection-count contention gate (e.g. `set_event_plane`'s "refuse while
  another backend is connected") passes or fails inconsistently, or silently proves nothing
  (the gate opens when it should refuse). Cause: `pg_stat_database.numbackends` is a live count —
  if you open a throwaway connection to read it and then drop it before opening the connection
  under test (or the "other session" you're proving refuses the switch), the drop and the new
  connect race, and the count you captured no longer matches the count at call time. Fix: measure
  through a connection the test keeps open for the rest of the case (an `observer`), never a
  fresh one you open-query-drop; and always measure `own_backends` *at* the moment you know what
  should count as "mine" (immediately before opening the connection under test, or immediately
  after the deliberately-uncounted "other" session connects) rather than passing a literal
  constant. See `lore-postgres/tests/domain_outbox_event_plane.rs`'s `total_backends` helper for
  the worked pattern (six of seven cases needed it before this lesson, all six failed the same
  way: "N other backends" where N included the test's own leftover setup connections).
- **A plan-shape gate needs three parts, and a control that can go red.** Read the statement
  inventory from source (the `*_cached(` literals) so a new statement cannot dodge the gate;
  `PREPARE` each under `SET plan_cache_mode = force_generic_plan` and `EXPLAIN (FORMAT JSON)
  EXECUTE` it with every parameter `NULL` (the generic plan ignores values, `simple_query` returns
  the JSON as text); then prove sensitivity by planning the same statement re-spelled with a bound
  state list and asserting it loses the partial index. `pg_prepared_statements.custom_plans` /
  `generic_plans` (PG14+) observes which plan ran, with an `auto` session as the control. Worked
  example: `lore-postgres/tests/statement_cache_live.rs`.
- **Stage-custody ledger tests: assert the ledger against the rows, and build both tombstone kinds
  on purpose.** Symptom: a counter test passes while a metadata row leaks or is refunded twice.
  Do: call `tests/common/stage_invariant.rs::assert_stage_ledger_matches_custody(url)` (usage
  `metadata_rows/bytes`, `live_*` vs the custody table, read straight from SQL) after every stage
  case. A tombstone that must stay needs the head still at the epoch with no epochs row (`begin_stage`,
  `withdraw_stage`, cleanup). A deletable one needs a PURGED staged epoch (stage, `commit_staged`,
  promote, cleanup). A guardrail needs a tiny `max_metadata_rows`
  (`stage_policy::initialize_with_limits`). Reference: `lore-postgres/tests/fragment_stage_tombstones.rs`.
- **A pool test that holds every slot and then checks out once more hangs forever.** The default
  `deadpool` pool has no wait timeout, so the test sits at 0 CPU, not failing. Drop the held guards
  first. Kill a hung live test by its test-binary name only; `Stop-Process` on every `cargo` also
  kills other lanes' builds in the shared checkout.

- **Refresh-read generations (WP-120)**: handlers read `lore_domain_*.generation` through
  `DomainContext::store().repository_snapshot/branch_snapshot`. Unit tests script them with
  `lore-server/tests/unit/grpc/generation_store.rs` (`GenerationStore::new(repo_gen, branch_gen)`; every
  other trait method panics). Live proof is `lore-postgres/tests/run-sweep-reads-live.ps1`
  (`lore-server/tests/sweep_reads_live.rs` plus the `wp120_` cases in `p12_lock_service_fenced_routing.rs`):
  real `repository_get`/`branch_get` handlers over `PostgresMutableStore` + a local immutable store,
  writes through the governed coordinator, and every response generation compared with a direct SQL
  read of the table (never the handler as its own oracle). Mutation probe: change one
  `to_wire(snapshot.generation)` in `lore-server/src/domain/read_generation.rs` to `.min(1)`.
- **A runner with a prefix-policed non-exact target** (`ExactPrefixes = @('wp120_')`) lets a new live
  case in a shared integration-test file join the inventory without claiming the whole file.
- **Formatting without touching a concurrent lane's files**: `rustup run nightly rustfmt --edition 2024 <your files>`
  instead of `cargo fmt -p`, then `cargo +nightly fmt -p <crate> -- --check` to confirm.

- **Live `p12_lock_service_fenced_routing` cases need one fresh database each.** Symptom: running the whole
  file with `-- --ignored` on one `LORE_TEST_PG_URL` fails ~9 cases that pass alone. Cause: each case
  bootstraps/arms the fenced schema itself. Do: `CREATE DATABASE` per case and `--exact`, as
  `lore-postgres/tests/run-sweep-reads-live.ps1` does; register a new `wp120_` case in that runner's
  `Cases` or its prefix guard refuses to start. A fake verifier that fails on demand is
  `DirectEchoVerifier::failing(Status)` in that file; assert receipt absence with
  `SELECT count(*) FROM lore_domain_operation_receipts WHERE client_attempt_id = $1` and keep a
  positive control that a served lock files exactly one row.
- **Proving a `lore-transport` client-classification test red pre-fix**: reverse-apply only
  `lore-transport/src/error.rs` and `src/grpc/mod.rs` (patch file in scratch, `git apply -R`, run,
  `git apply`, touch both files, compare `git diff` hashes). Reverting `outcome.rs` too breaks the
  `lore_revision::live_fixture` build, which names its public key const. The live repro is
  `lore/tests/live_lock_journal.rs` driving `RpcOutcome::RefuseNotPrepared(NotPreparedProof::..)`.
- **clippy `large_futures` in a transport test** -> `Box::pin(with_reconnect_classified(..))` inside the
  one helper that dispatches, not in each caller.
- **`cargo clippy ... -D warnings` on Windows stops at upstream-identical files** (`lore-revision/src/util/fs.rs`,
  `lore/src/remote/network/windows.rs`, unused imports in several `tests/unit` files). Rerun without `-D`
  and read only the files you touched.
- Source-pin tests (`include_str!` of `src/fragment_write_behind.rs` with `find("...\n            );")`) hold indentation: moving a block one level deeper fails them with an `expect` panic, not a behavior fault. Re-anchor the string, keep the ordering assertion (`tests/unit/fragment_write_behind.rs`).

## Histogram/quantile fixtures

- **Testing a quantile-from-bucket-counts function without re-deriving its formula**: build a fixture
  where sample *rank* maps monotonically and known-in-advance to a bucket index (e.g. rank `i+1` in
  bucket `min(i, last_bucket)`), then hand-compute the expected bucket per `(n, q)` pair from the
  fixture's construction, not from a copy of the function's own rank formula — otherwise the test
  only checks the implementation against itself. Use sample counts spanning `n*q` fractional
  (discriminates `ceil` vs `floor`) and exact-integer cases, and place values mid-bucket (not on a
  boundary) unless the test's specific point is boundary inclusivity. See
  `lore-telemetry/tests/unit/pool_acquire.rs::record_ranked_samples` /`wait_in_bucket`.

## CR-038 forward-upgrade fixture gotchas

Seeding `drain_spool_custody`/`object_dispatch_spool_objects` rows directly (bypassing the full
reserve/claim/release algebra) and driving real reservation traffic through `DrainClient` both hit
the same class of trap: a CHECK/FK constraint that looks satisfied by inspection but isn't, because
it's derived from another column rather than a fixed literal.

- **`*_uuid_unix_ms` CHECK columns are derived, not free-form.** `object_dispatch_requests` (and
  siblings) pin `logical_request_uuid_unix_ms`/`attempt_uuid_unix_ms` to the exact 48-bit big-endian
  millisecond timestamp the matching UUIDv7 embeds in its own first six bytes. A hand-picked literal
  (e.g. `1000`) only passes when the fixture also hand-picks a UUID whose embedded timestamp equals
  it; a real `Uuid::now_v7()` needs the value computed from `id.as_bytes()[0..6]`, not asserted.
- **A BEFORE INSERT trigger can require a JSONB field to *name* an unrelated row.**
  `drain_custody_policy_expiry_v1` (0027) does `SELECT ... INTO STRICT NEW.policy_expiry_ms FROM
  drain_policies WHERE revision = NEW.descriptor->>'policy_revision' AND
  encode(digest,'hex') = NEW.descriptor->>'policy_digest'` — an empty or placeholder `descriptor`
  JSONB on a directly-seeded `drain_spool_custody` row fails this lookup with a bare "query returned
  no rows", not a named constraint. The descriptor must carry the seeded policy's own revision and
  hex digest even when nothing else in the descriptor is realistic.
- **A composite FK can reference a column that "looks" free-form.**
  `object_dispatch_spool_objects.bound_request_*` FK-references `object_dispatch_requests` on
  `(logical_request_id, attempt_id, terminal_result_id)` — the three values must match a seeded
  request row *exactly*, including `terminal_result_id`, which is easy to drift into a
  differently-spelled placeholder string across two independently-written INSERTs.
- **Through R30, `drain_cleanup_release_v1` needs a real BLAKE3 provider even when the test's point
  is the metadata true-up, not the release receipt.** It called `local_blake3_v1` to sign the
  receipt; without `public.blake3(bytea)` every path through it failed with
  `LOCAL_BLAKE3_PROVIDER_UNAVAILABLE`. From R31 (migration 0031) it signs nothing and needs no
  provider; only R25-R30 fixture cells (`install_cell_schema_at`) still do.
- **`drain_cleanup_claim_v2` (0029; `_v1` before it) refuses `DRAIN_CLEANUP_TOO_EARLY` until the
  reservation's own expiry passes.** A back-to-back reserve→claim→release fixture needs a short
  `maximum_ttl_ms` on the policy/descriptor and a sleep past it before claiming. The first window
  must also absorb a cold `DispatchRuntimePool`'s connect-and-attest round trip (seconds): warm the
  pool with any cheap call before the timed loop.
- **Whitespace inside a plpgsql `$$...$$` body is part of `prosrc`.** A test that restores a function
  (undoing planted catalog drift or a mutation) must reproduce the exact text, comments included, or
  the `functions` manifest section reads `CatalogDrift`. Prefer `include_str!` of the real migration
  plus substring extraction over retyping, and diff the extract first.
- **A shared fixture row (one `drain_policies` row per boundary/cell reused across cases) needs
  `ON CONFLICT DO NOTHING` on re-seed, plus a top-up of any row a prior case's release decremented**
  (`object_dispatch_quota_usage`, keyed `(provider_boundary_id, scope_kind, scope_id, quota_class)`).
  Otherwise re-insert fails, or `DRAIN_COUNTER_UNDERFLOW` fires instead of the exception under test.
- **A raise inside a plain `batch_execute` string leaves session state dirty.** `SET SESSION
  AUTHORIZATION x; BEGIN ...; SELECT <raises>; COMMIT; RESET SESSION AUTHORIZATION;` aborts at the
  failing statement and never reaches `RESET`. Run `ROLLBACK; RESET SESSION AUTHORIZATION;` before
  reusing that client.

- **A raw TCP fault proxy scanning client->server must relay the pgwire startup packet first.** Every
  later message has a leading tag byte before its 4-byte length; the startup packet (and a preceding
  `SSLRequest`, absent with `sslmode=disable`) does not. Relay it verbatim by its untagged framing,
  or the proxy misreads its first byte as a tag and hangs.
- **A `uint64` domain column needs its bound parameter cast to the driver's type first.**
  `$1::object_store_retention.uint64` or `$1::numeric` from an `i64` fails as `WrongType`;
  `$1::bigint::numeric` or `$3::text::object_store_retention.uint64` works.
- **`drain_cleanup_compact_v2` (0029; `_v1` before it) silently no-ops when no matching
  `object_dispatch_spool_objects` row exists, unless the policy's `expires_at_ms` is already past.**
  Its guard is `greatest(s.expires_at_unix_ms, policy.expires_at_ms) > now`; a zero-row `SELECT INTO`
  leaves `s.expires_at_unix_ms` NULL and `greatest(NULL, far_future)` is `far_future`. Other
  fixtures seed a far-future expiry to keep compaction a no-op; a case that needs compaction to run
  must seed a PAST `expires_at_ms`.
- **A "no other session connected" precondition counts YOUR test's own connections.**
  `upgrade_cell_schema`'s D4 check (gates only the real N-1 to N transition, not an already-current
  call) counts the admin connection and any `DispatchRuntimePool` connection. Before the one real
  transition, drop every other handle (admin client, pool/`DrainClient`, second migrator) and poll
  `numbackends - 1` from `pg_stat_database WHERE datname = current_database()` to zero from the
  surviving connection. An `AbortOnDropHandle` abort does not mean the server saw the socket close.
- **`ReservePutRequest`'s `*_blake3` fields are opaque 32-byte tokens, not hashes the client must
  derive.** `reserve_put` stores them unchecked. Through R30 the shared codec (0009) still needed a
  real `public.blake3(bytea)`, so an R25-R30 fixture without a provider failed
  `reserve_put`/`put_upload_progress`/`put_spool_ready` with `LOCAL_BLAKE3_PROVIDER_UNAVAILABLE`;
  install the genuine `plpython3u` provider (`run-cell-schema-forward-upgrade-live.ps1`'s image) for
  those. From R31 none is needed.
- **A `CREATE TABLE`/`DROP TABLE` drift probe can flake a following D4 check.** The dropped table
  can attract a stray autovacuum backend that `wait_until_exclusive` loses a race to. Probe catalog
  drift with `CREATE OR REPLACE FUNCTION`/`DROP FUNCTION` unless the probe needs relation behavior.

- **Prove an unrelated row set is untouched with counts captured before and after the mutation.**
  R25 budget tables (`object_dispatch_budget_configurations`/`_current_budget_configuration`/
  `_budget_bucket_state`, scoped by `provider_boundary_id`): assert the exact tuple both sides
  (`(1, 1, 7)` for one budget; 7 = the `1..=7` cap-class loop in `publish_budget`). A refusal that
  names a remedy should also assert it does NOT suggest an unrelated one (e.g. "wait for
  retention"). See `budget_row_counts` and the two R25 refusal tests in
  `cell_schema_forward_upgrade_live.rs`.
- **A real `reserve_put` always charges quota alongside the spool row**, so a fixture cannot
  isolate "spool object present, quota untouched" through it. Mutation proof: with the R25 prelude's
  spool-objects `IF EXISTS` disabled, the same database still refused, with the quota-charge
  message. The two R25 guards are independently reachable.

See `lore-object-dispatch/tests/cell_schema_forward_upgrade_live.rs` for the resulting fixture
(`seed_metadata_true_up_fixture`, `synthetic_descriptor`, `wait_until_exclusive`,
`admit_one_reserved_spool_object`) and `run-cell-schema-forward-upgrade-live.ps1` for the dedicated
BLAKE3-capable container.

## R31 (migration 0031, BLAKE3 leaves PostgreSQL) fixture gotchas

- **`new row ... violates check constraint "..._record_blake3_null_ck"` on a seeded row.** From R31
  `object_dispatch_spool_objects.record_blake3`, `.reserve_put_ack_blake3` and
  `object_dispatch_dispatchers.record_blake3` are NULL by CHECK, and 0007's "bytes end with the
  digest" CHECKs are gone. A direct INSERT must write NULL there (`tests/common/cell_retention_rows.sql`,
  `seed_metadata_true_up_fixture`). `release_receipt_blake3` on a lifecycle-3 spool row is separate:
  it keeps its presence and tail-equals-digest CHECKs, so `cell_retention_live.rs` writes a literal
  32-byte value and bytes that end with it.
- **A full-chain tier cannot reach reserve or ready through the runtime role as 0026 left it.**
  0026 revoked runtime EXECUTE on the raw `reserve_put`/`put_upload_progress`, and
  `put_spool_ready_v1` refuses `DRAIN_READY_EXPIRED_OR_FENCED` without live drain custody under an
  unexpired policy. `dispatch_client_live.rs` re-grants the two raw procedures as the superuser and
  seeds the policy and custody pair (the custody insert trigger needs a descriptor naming the
  policy's revision and hex digest); the ready procedure still runs for real.
- **Expected v2 bytes come from the row's input columns, built by hand.** `dispatch_client_live.rs`
  assembles each fixture-constant preimage; `cell_schema_forward_upgrade_live.rs` (`SpoolInputs`,
  `ack_v2`, `row_v2`) rebuilds a backfilled row from the columns the database did not compute.
  Never call a SQL codec to build the expectation. Children are framed `u32 length || preimage`; the
  reservation and ready rows no longer carry the raw ack digest.
- **The R31 participant commitment is SHA-256, computed by `tests/common/sha256.rs`** (NIST-vector
  `self_check`, no new dev-dependency). The database's own `sha256()` would make the expectation
  circular. A participant enrolled under the old BLAKE3 commitment must fail to authenticate.
- **Pin the cut by measuring it.** Tampering the stored ack in place is still refused (every replay
  recomputes ack and record from the columns and compares bytes); tampering the stored release
  receipt is not noticed, because nothing reads it back. A policy digest that is not the policy's
  BLAKE3 publishes and reads back at the database, and only `DrainClient::read` refuses it
  (`DrainError::Invalid`, not `Refused`, which tells Rust's refusal from the database's).
- **The release underflow discrimination proof reads the function from 0031's text**
  (`real_release_function_body`) and mutates the guard with a replace that asserts it matched, so
  there is no second hand-copied literal to drift.
- **`lore-postgres/tests/run-write-behind-linux.ps1` defaults to plain `postgres:18-bookworm`.** Its
  Linux target volume is ~64 GB; a second `-RunNamespace` doubles that and does not fit beside it on
  C:. Run it on the default volumes, and only when no other lane's `wb-linux-*` container is up.
## CR-039 fragment-schema-upgrade fixture gotchas

Building a revision-4 clean-cell fixture by clean-initializing (reaching the compiled revision) then
downgrading in place, rather than replaying `dae71dfc` DDL, hits three independent traps —
each one made `upgrade_clean_schema` return a *different* refusal than the one the case meant
to exercise, not a compile or connection error, so each needed its own repro to place:

- **A bare stage-table `DROP TABLE ... CASCADE` does not remove every stage-5 object.**
  `lore_fragment_stage_drain_recovery` is a partial index on `lore_fragment_lifecycle` (the
  *base* revision-4 table), not on any dropped stage table — CR-039's own doc says so
  ("partial, on `lore_fragment_lifecycle`") but it's easy to read past. Leaving it behind reports
  `stage_indexes: 1` in the unknown-catalog-state refusal, on a fixture that otherwise looks
  exactly revision-4. Drop both `lore_fragment_stage_custody_cleanup` and
  `lore_fragment_stage_drain_recovery` explicitly, by name, after the table drops.
- **`clean_readiness_holds`'s sequence-headroom check is a strict `>`, and a fresh clean cell
  sits exactly on that boundary.** `lore_fragment_fence_seq` starts at `last_value = 1,
  is_called = false`, so `last_value + (is_called?1:0) = 1`. Any raw test row (a lifecycle head,
  a staged lease) carries `last_fence`/`fence`/`reader_fence >= 1` by CHECK, and the schema's own
  minimum legal value, `1`, ties the boundary rather than clearing it — `1 > 1` is false. The
  refusal reads as "enforcement, fencing, sequence headroom or readable heads do not hold", which
  has nothing to do with the head or lease the case meant to plant. Call
  `SELECT nextval('lore_fragment_fence_seq')` (twice, to be safely clear) before any such raw
  insert.
- **`repository_create` requires an exact `EpochWitness` per metadata hash once lifecycle is
  enabled — true of every clean-initialized cell, including at revision 4.** A repository fixture
  built with random `metadata_hash`/`default_branch_metadata_hash` bytes and no
  `metadata_witnesses` refuses `repository_create_metadata_witnesses_required`. Publish the two
  hashes as real Remote fragments first (`begin_direct_write`/`commit_remote`), capture each
  witness via `capture_current_readable_epoch_for_authority`, and pass both — `bind_creation_metadata`
  associates them to the new repository at the zero context internally, not a context the caller
  picks.
- **A fresh-vs-upgraded catalog diff must compare two *clean* cells, not a clean cell against a
  plain `bootstrap()`.** The six `lore_clean_*`/`lore_membership_*` trigger installs live in
  `initialize_empty`, not in `bootstrap()` — a plain-bootstrapped comparison cell has zero of them,
  which any trigger-inclusive fingerprint reports as a huge, misleading divergence with nothing to
  do with the upgrade path itself.

See `lore-postgres/tests/domain_fragment_schema_upgrade.rs` for the resulting fixture
(`revision6_clean_cell`, `revision4_clean_cell`, `advance_fence_sequence`) and
`run-fragment-schema-upgrade-live.ps1` for the Postgres-only container (no MinIO/S3: the upgrade
never touches a provider).

**The backend-count guard refuses on the fixture's own assertion connection.**
`upgrade_clean_schema` calls `refuse_other_backends` (`pg_stat_database.numbackends` minus the
coordinator's pool size) before classifying the catalog, on every call including a no-op
`AlreadyCurrent` rerun. A test's own `direct: Client` counts as "another backend" and the call
refuses for the wrong reason. Drop `direct` right before each `upgrade_clean_schema`/`assert_refused`
call and reconnect after (`call_upgrade`/`expect_upgraded`/`assert_refused_dropping` in
`domain_fragment_schema_upgrade.rs`, mirroring `wait_until_exclusive` in
`lore-object-dispatch/tests/cell_schema_forward_upgrade_live.rs`). The guard's settle loop
(`BACKEND_SETTLE_ATTEMPTS`/`BACKEND_SETTLE_INTERVAL`, ~2s) absorbs an in-process drop. **Across a
separate OS process** it does not: `lore-server/tests/fragment_schema_upgrade_operator.rs` polls
`numbackends` to zero before launching the second `loreserver`.

Because any second connection trips the count check first, no ordinary second connection reaches the
`LOCK TABLE ... NOWAIT` backstop. The `a_live_lock_holder_...` and
`a_realistic_row_exclusive_writer_refuses_while_another_session_is_connected` tests therefore assert
the exact count message (`"other backend(s) are connected"`), not just `Contention(_)`. The failpoint
`schema_upgrade.drain.before_update` pauses the upgrade between the count check and the lock;
`the_nowait_backstop_refuses_a_lock_holder_that_races_the_backend_count` (a `failure_generator`
build, armed per case by `run-fragment-schema-upgrade-live.ps1`) asserts the NOWAIT message.

To fail one statement inside a multi-statement `batch_execute` without touching production code,
use an event trigger (`CREATE EVENT TRIGGER ... ON ddl_command_start WHEN TAG IN ('ALTER TABLE')`,
gated on `current_query() LIKE '%<string unique to the target DDL>%'`). Pair it with a positive
control (`RAISE ... USING ERRCODE` on a throwaway connection) proving the SQLSTATE the coordinator's
`pg()` wrapper surfaces.

## General Pitfalls

- **Hashing output for whitespace**: Hashing ignores `\r\n` vs `\n` normalization in pipelines. Use `SELECT position(chr(13) in prosrc)` or `.gitattributes` `eol=lf` limits instead.
- **Poisoning cache fields**: If you poison an in-memory `State`/`Tree` for a fault-injection, call `state.mark_dirty()` or it will not serialize.
- **Capturing LoreEvents**: Always drain to `LoreEvent::End`, not just the first event, as initial events might be non-terminal.
- **Agreement tests**: When two validators check the same field, test their agreement explicitly, not just rejection.
- **Negative controls**: A test asserting "no error" must have a companion positive control proving the success path is actually run.
- **Public stage concurrency**: Test multi-worker lifecycle with a Tokio multi-thread runtime.
- **Doc comments**: Module doc comments can trip source-pin scans if they name forbidden words. Use exact syntactical shapes instead.
- **Process-global state**: OTel, auth caches, etc., are shared. Avoid assertions on global emptiness.
- **Staging I/O permit waits** (`write_behind/root.rs`): `io_permit_within` records the refusal counter and wait histogram through `OnceLock` global instruments, and `opentelemetry_sdk` is not a dev-dependency, so no test asserts counter values. Pin the returned `Io { "staging I/O capacity", WouldBlock }` plus `store_error().is_slow_down()` instead, and say counters are unasserted. Pool-policy tests are `cfg(all(test, unix))` in `durability_tests.rs`, so they run only under `run-write-behind-linux.ps1`.
- **A red drain test beside your change is not yours until proven**: in a shared tree another lane's drain-order edits (random cursor, shuffled batch) fail `adapter_parallel_drain_*` and `small_worker_batches_*` live cases that assume ascending hash order. Check `git diff` of `store/fragment_write_behind.rs` before blaming a permit or read-path change.

## AWS SDK specifics

- Include explicit `ErrorMetadata.code(...)` for exceptions.
- Adaptive retry's rate limiter is shared. Keep `Standard` mode unless overridden. `Disabled` mode applies one attempt only.

## PowerShell live-test scripts

- **Argument arrays**: Build command arguments as an array (`$args = @(...)`) and use splatting (`& cmd @args`) instead of backticks.
- **Output truncation**: `Format-Table` truncates to console width; use `Out-String -Width 200`.
- **Line continuations**: `+` continues an expression, not a command. Assign to a variable first.
- **Echo captured cargo output**: Gate 0 receipt producers parse cargo's `test result: ok. N passed; ...` lines from runner stdout. A runner that captures `$output = & cargo ... | Out-String` must `Write-Host $output` right after `$exitCode = $LASTEXITCODE` (inside the `try`, so a throwing `finally` cannot lose it), or the row reads FAIL with a green run. Do not also echo on the pass branch, or the counts double.
- **List diffs**: Cross-check hardcoded live-test targets against `cargo test --list`.
- **Piping to head**: `script | head` can SIGPIPE without killing detached containers. Redirect to files.
- **Container ownership**: Confirm container ownership (e.g. by pid label) before removal.
- **TLS-only Postgres fixture** (`run-cell-schema-install-live.ps1`, second container): start the stock image, `docker exec --user root` `openssl req -x509 ... -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:FALSE` (a CA-flagged self-signed cert used as end entity is refused by webpki), chown/chmod 600 the key, rewrite `$PGDATA/pg_hba.conf` to `hostssl`-only, `ALTER SYSTEM SET ssl/ssl_cert_file/ssl_key_file` + `pg_reload_conf()`, then poll `SHOW ssl` and `pg_hba_file_rules` errors. The cert is its own CA; connect as `localhost` (SAN) and use `127.0.0.1` for the host-mismatch negative case. Give both containers the same ownership label so the collision guard and teardown cover both.
- **Substring source guards vs. docs**: `cell_schema_install.rs`'s "no service shell" scan of the bin source must skip `//` comment lines; prose such as "the server is verified" contains `serve`.

## Running Unix-only tests on Windows (Docker Desktop)

1. **Scratch copy**: Copy working tree to a scratch directory (`robocopy <repo> <scratch> /E /XD target .git`) to avoid read-only or concurrent mutation issues.
2. **Volumes**: Use named Docker volumes for `CARGO_TARGET_DIR` and the cargo registry cache.
3. **Environment**: Base image `rust:slim-trixie` needs `protobuf-compiler libprotobuf-dev build-essential`. Add `clippy` via rustup if needed.
4. **Execution**: Run detached, poll `docker inspect` for status, then remove.
5. **Fixture manifests**: If a test runs `cargo check --offline` on a fixture crate, prefetch it with `cargo fetch --manifest-path <fixture>/Cargo.toml` first.
6. **Port allocation**: Avoid `bind(0)` when both TCP and UDP ports are needed; Windows has disjoint UDP/TCP reservations. Sample randomly instead.
7. **Deliberate aborts fill C: under WSL**: WSL 2.7.3 pipes every core dump (Docker containers included) to its own collector, writing a ~6.8 GB dump per abort to `%LOCALAPPDATA%\Temp\wsl-crashes` (default keeps 10; 53 GB in two runs killed Docker Desktop). `ulimit -c 0` is IGNORED when `core_pattern` is a pipe; a limit of 1 makes the kernel skip the piped dump. An entrypoint `ulimit` does not reach `docker exec` children, so set it on the container: `docker run --ulimit core=1:1`. `run-write-behind-linux.ps1` does this for its build container. Check `wsl-crashes` is empty after any run whose tests abort on purpose (failpoint crash-recovery). Host fallback: `.wslconfig` `[wsl2] maxCrashDumpCount=-1`.

## Async timing tests in `lore-postgres`

- **`start_paused` fails with E0599 on `Builder::start_paused`; `tokio::spawn` fails clippy** ->
  `lore-postgres` needs the `tokio` `test-util` dev-dependency (workspace tokio lacks it), and the
  workspace `clippy.toml` bans `tokio::spawn`/`JoinSet::spawn` while `lore_spawn!` escapes paused
  time. Drive concurrent contenders on one task with `tokio::join!` or a poll-all helper; see
  `lore-postgres/tests/write_behind_drain_reserve.rs`.
- **Appending to an `eol=lf` file with `Add-Content` writes CRLF** -> rewrite with
  `[IO.File]::WriteAllText` and an LF-normalised string, then `git ls-files --eol <path>`.
- **`lore-integration-tests --features integration_tests` has 51 pre-existing failures without LocalStack/Dynamo** (`aws_store_test` 30, `locks_test` 14, `dynamodb_test` 7). They are infra-gated, not regressions; filter them out (`-- storage_copy_on_write quic_strict_admission`) rather than reading the red as yours.

## R32 (migration 0032, WP-115 f2) fixture gotchas

- **From R32 `DrainClient::release_cleanup` deletes the row** (release then `drain_cleanup_compact_v3`), so a case that reads a
  released row, a receipt, or a marker afterwards finds nothing. Use `release_without_compaction`
  (raw `drain_cleanup_claim_v2` + `drain_cleanup_release_v1`, state 3) and `DrainCell::become_legacy_marker` (the pre-R32 state-4
  shape) in `cell_schema_forward_upgrade_live.rs`. A cell at its row cap can only be built from those shapes now.
- **Assert the ledger, not just the call**: `assert_ledger_matches_custody` (rows == count, bytes == sum, per boundary/cell) after
  every cycle; add `rows_below_the_floor` (custody `drain_uuid_v7_ms_v1(attempt_id)` < `retired_floor_ms`) for floor cases.
- **Reserve needs UUIDv7 ids and a chosen timestamp**: `uuid_v7_at(ms, salt)`; `Uuid::new_v4()` or md5-derived ids are refused
  `INVALID_UUIDV7` (22023, from the canonical-bytes encoder, the only `UUIDv7` refusal; Rust's `canonical_bytes` also refuses non-version-7, so forge canonical bytes to reach SQL), and legacy md5-seeded custody rows decode to NULL (never hold the floor).
- **Race the floor with two plain runtime sessions**, not the pool: `serializable_statement` returns `(sqlstate, message)`;
  accept 40001/40P01 and `55000 DRAIN_ATTEMPT_RETIRED`, assert no row below the floor. Reset between iterations with
  `wipe_custody` (owner role), and take the "advance first" order by opening the reserve's snapshot with a cheap read first.
- **A subcommand gated on an env var is testable without a database**: closed port + exit code 2 (refused before connecting) vs 1
  (reached the connection attempt), as `cell_schema_install_tls.rs` does for `LORE_OBJECT_DISPATCH_CELL_UPGRADE_BACKUP_REF`.
- **Runner inventories pin test names**: `paired_rotation_refuses_live_spool_then_preserves_compact_markers_and_usage` keeps its
  name (Gate 0 receipts key on it) though it no longer holds compact markers. New live cases join
  `run-cell-schema-forward-upgrade-live.ps1`'s `$tests` (one database each), `run-local-authority-live.ps1`'s known list, and
  `run-write-behind-linux.ps1`'s `$libUnixOnlyLive` / `spool_writer` floor.
- **The 64-cycle guardrail costs ~16 x 3.5 s**: a cycle cannot be claimed before `maximum_ttl_ms` passes, so the cap-4 case runs
  16 batches of 4. The provider-level Linux run of more fragments than `metadata_max_rows` (1000 in the fixture) is not feasible
  in the same way; the SQL tier carries the proof.
