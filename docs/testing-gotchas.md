# Durable test patterns and gotchas: `tideshift/main`

Durable, recurring testing lessons grouped by topic.

## Build and merge hygiene

- **Rebuild test targets after merge**: Signature changes might not break `cargo build` but can break `cargo test`.
- **Incremental state issues**: If untouched files report impossible errors, clean the affected crate.
- **Timing-sensitive tests**: Rerun failures in isolation; they might be scheduling flakes under load.
- **Protobufs**: Regenerate instead of hand-splicing. Box large `prost` oneofs to avoid large enum variants and pin the boxed shapes.
- **Clippy**: Check crate-local `clippy.toml` which shadows workspace configs.
- **A restored file can still test red**: after a mutation-probe restore (or any rapid overwrite of a
  source file) under heavy concurrent `cargo` activity in a shared `target/` dir, a rerun can reuse a
  stale compiled test binary and silently reproduce the reverted mutation — no `Compiling <crate>`
  line appears in the output, only `Finished`. Confirm the on-disk source first (`Read` it back), and
  if a rerun after a confirmed-correct restore still fails, bump the file's mtime
  (`(Get-Item $f).LastWriteTime = Get-Date`) to force a real recompile before trusting the result.

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

## Fixtures and white-box seams

- **Identity preservation**: Versioned derivations must preserve old identities. Test V2 successors against explicit V1 predecessors.
- **Testing scope**: Same-file `#[cfg(test)] mod tests` can inspect private state, sibling modules cannot.
- **Immutable-store fixtures**: Use behavior-based fixtures (canned responses, selective fault injection).
- **Mock state**: Use `Arc`-backed counters/maps for shared observation.
- **Thin wrappers**: Test wrappers directly to catch dropped/delegated arguments.
- **Cross-repo fixtures**: For paths like `../../lorehub/...`, skip gracefully if the sibling repo is absent, but panic if the path is explicitly requested but missing.
- **Fault injection**: Inject faults by key identity rather than call ordinal. Stand in for real-process conditions by calling production write paths directly to ensure real fences are exercised.

## Postgres & Database Testing

- **250ms DDL limit**: `lore-postgres` bootstrap DDL has a 250ms limit; it can fail on a loaded host. Wait and retry rather than debugging a fresh container.
- **Parameter typing**:
  - Client-side `WrongType`: Cast bound SQL types explicitly (e.g. `$2::smallint::text`).
  - `42P08` inconsistent types: Do not reuse placeholders (`$1`) for different column types even if the Rust value is the same. Use unique placeholders (`$1`, `$2`).
- **Retry classification**: Retries should not be triggered by broad transience classifiers for `40001`/`40P01`.
- **Locking order**: Fanout helpers using `LockSequence` must lock earlier classes *before* the caller's lock, not after.

## Histogram/quantile fixtures

- **Testing a quantile-from-bucket-counts function without re-deriving its formula**: build a fixture
  where sample *rank* maps monotonically and known-in-advance to a bucket index (e.g. rank `i+1` in
  bucket `min(i, last_bucket)`), then hand-compute the expected bucket per `(n, q)` pair from the
  fixture's construction, not from a copy of the function's own rank formula — otherwise the test
  only checks the implementation against itself. Use sample counts spanning `n*q` fractional
  (discriminates `ceil` vs `floor`) and exact-integer cases, and place values mid-bucket (not on a
  boundary) unless the test's specific point is boundary inclusivity. See
  `lore-telemetry/src/pool_acquire.rs::tests::record_ranked_samples` /`wait_in_bucket`.

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
- **`drain_cleanup_release_v1` needs a real BLAKE3 provider even when the test's point is the
  metadata true-up, not the release receipt.** It calls `local_blake3_v1` unconditionally to sign
  the release receipt; without `public.blake3(bytea)` installed, every path through this function —
  including the underflow case — fails with `LOCAL_BLAKE3_PROVIDER_UNAVAILABLE` before reaching the
  logic under test.
- **`drain_cleanup_claim_v1` refuses `DRAIN_CLEANUP_TOO_EARLY` until the reservation's own expiry
  passes.** A fixture driving reserve→claim→release back-to-back (to simulate load quickly, not a
  realistic multi-minute TTL) must give the policy/descriptor a short `maximum_ttl_ms` and then sleep
  past it before claiming — and that window must absorb a *cold* runtime pool's first
  connect-and-physical-attest round trip (seconds, not milliseconds) if the very first reservation in
  a test uses an unwarmed `DispatchRuntimePool`. Warm the pool once (any cheap call) before the timed
  loop starts, then the per-iteration window only needs to cover normal round-trip time.
- **Whitespace inside a plpgsql `$$...$$` body is part of `prosrc`, verbatim.** A test that restores
  a function to its "original" definition (to undo a planted catalog drift, or to restore a
  temporarily mutated function for a discrimination proof) must reproduce the exact source text,
  comments included — `pg_get_functiondef` reconstructs a plpgsql body from the stored `prosrc`
  unchanged, so any difference in indentation or a dropped comment line still reads as `CatalogDrift`
  on the `functions` manifest section, even though the logic is identical. Prefer `include_str!` on
  the real migration file plus a plain substring extraction over hand-retyping the body, and diff the
  extracted text against what you intend to keep unmutated before relying on it.
- **A shared fixture row (one `drain_policies` row per boundary/cell reused across several test
  cases) needs `ON CONFLICT DO NOTHING` on re-seed, and a matching top-up on any row a prior case's
  release decremented** (`object_dispatch_quota_usage`, keyed by `(provider_boundary_id, scope_kind,
  scope_id, quota_class)`) — otherwise the second case either fails re-inserting the policy row, or
  the wrong exception fires (`DRAIN_COUNTER_UNDERFLOW` instead of the one actually under test)
  because a prior case already spent that scope's counted usage.
- **A raise inside a function called through a plain `batch_execute` string leaves the connection's
  session state dirty.** `SET SESSION AUTHORIZATION x; BEGIN ...; SELECT <raises>; COMMIT; RESET
  SESSION AUTHORIZATION;` never reaches the `COMMIT`/`RESET` when the `SELECT` raises — the whole
  batch aborts at the first failing statement. A test asserting an expected raise on such a
  connection must `ROLLBACK; RESET SESSION AUTHORIZATION;` explicitly before reusing that client.

- **A raw TCP fault proxy that scans the client->server direction must forward the pgwire startup
  packet specially first.** Every message after it carries a leading tag byte before its 4-byte
  length; the startup packet (and a preceding `SSLRequest`, absent when connecting with
  `sslmode=disable`) does not -- it is just the length followed by that many bytes. A proxy written
  to scan for a needle (or any other tagged-frame parsing) must relay this first message verbatim,
  by its own untagged framing, before switching to tag-based parsing, or it misreads the startup
  payload's first byte as a tag and hangs waiting for a length that never resolves.
- **A `uint64` domain column needs its bound parameter cast to its own underlying type first, not
  straight to the domain.** `$1::object_store_retention.uint64` or `$1::numeric` from an `i64`
  binding fails as a `WrongType` on the driver side; `$1::bigint::numeric` (cast to what the Rust
  type actually binds as, then to what the SQL expression needs) works. The existing
  `$3::text::object_store_retention.uint64` idiom used elsewhere in this crate sidesteps the same
  issue by going through text instead.
- **`drain_cleanup_compact_v1` silently no-ops when there is no matching
  `object_dispatch_spool_objects` row, unless the seeded policy's own `expires_at_ms` is already in
  the past.** Its early-return guard is `greatest(s.expires_at_unix_ms, policy.expires_at_ms) > now`;
  a `SELECT INTO` (not `STRICT`) that matches zero rows leaves `s.expires_at_unix_ms` NULL, and
  `greatest(NULL, far_future)` still evaluates to `far_future` -- every other fixture in this tier
  deliberately seeds a far-future policy expiry specifically to keep compaction a no-op, so a test
  that needs compaction to actually run must seed a PAST `expires_at_ms` instead, not merely omit
  the spool_objects row.
- **A "no other session connected" precondition counts YOUR test's own fixture connections.**
  `upgrade_cell_schema`'s D4 check (refuse the real state-transition step, not a no-op
  already-current call, if any other backend is connected to the cell database) counts the test's
  own admin/superuser connection and any `DispatchRuntimePool` connection just as much as a
  deliberately-opened "replica" session. Before the ONE call in a test that performs the real N-1→N
  transition, explicitly drop every other handle this test opened (admin client, pool/`DrainClient`,
  a second migrator connection) and poll `(numbackends - 1) FROM pg_stat_database WHERE datname =
  current_database()` down to zero from the surviving connection before calling — an `AbortOnDropHandle`
  aborting a background connection task doesn't guarantee the server has noticed the closed socket
  yet. A call already at the current state needs none of this (D4 only gates the one transition).

- **`ReservePutRequest`'s `*_blake3` fields are opaque 32-byte tokens, not hashes the client must
  derive.** 0013's `reserve_put` stores whatever bytes are supplied for `boundary_blake3`,
  `observation_binding_blake3`, `expected_blake3` and `put_reservation_fingerprint`; there is no
  server-side check that they are a real digest of anything. But the shared canonical-record codec
  (0009) it calls into DOES need a real `public.blake3(bytea)` provider to verify its own generated
  ACK digest — a fresh disposable database with no BLAKE3 provider installed fails every
  `reserve_put` call with `LOCAL_BLAKE3_PROVIDER_UNAVAILABLE`, even though nothing in the request
  itself "needed" hashing. Install the provider (the genuine `plpython3u` one from
  `run-cell-schema-forward-upgrade-live.ps1`'s image, not a golden-vector stand-in) before any real
  `reserve_put`/`put_upload_progress`/`put_spool_ready` call, not just before a release/compaction
  call.
- **A `CREATE TABLE`/`DROP TABLE` drift probe can flake a following D4 exclusivity check.** Planting
  catalog drift with a table (then dropping it to undo the plant) can attract a stray autovacuum
  backend shortly afterward; `upgrade_cell_schema`'s "no other session connected" poll
  (`wait_until_exclusive`) can read zero and still lose the race to that worker before the next
  call's own check runs. A `CREATE OR REPLACE FUNCTION`/`DROP FUNCTION` probe (no relation
  created or dropped) proves the same catalog-drift refusal without the relation-level autovacuum
  trigger; prefer it whenever the probe's only job is to change the manifest, not to test
  relation-specific behavior.

- **Proving a migration leaves an unrelated row set untouched needs counts captured on both sides
  of the mutation, not just a post-hoc "still not full" read.** For the R25 budget-limiter tables
  (`object_dispatch_budget_configurations`/`_current_budget_configuration`/`_budget_bucket_state`,
  scoped by `provider_boundary_id`), capture `(configurations, current, bucket_state)` before the
  upgrade and assert the exact tuple again after — `(1, 1, 7)` for one published budget (7 = the
  fixed `1..=7` cap-class loop in `publish_budget`). A refusal message asserting a remedy ("reinstall
  the cell" / "get an owner decision") should also assert the negative — that it does NOT suggest an
  unrelated fix (e.g. "wait for retention") — because an unfixable precondition and a merely-slow one
  read identically if only the positive claim is checked. See
  `budget_row_counts`/`live_install_at_r25_upgrades_to_current_and_drain_client_writes` and the two
  R25 refusal tests in `cell_schema_forward_upgrade_live.rs`.
- **A real `reserve_put` admission always charges quota alongside the spool row it creates**, so a
  fixture cannot isolate "spool object present, quota untouched" through `reserve_put` alone —
  proven by mutation: with the R25 prelude's spool-objects `IF EXISTS` disabled, the SAME
  reserve_put-seeded database still refused, but with the quota-charge message, because admission
  reserves quota units as part of the same call. Confirms the two R25 guards are independently
  reachable in practice, not merely in the SQL text.

See `lore-object-dispatch/tests/cell_schema_forward_upgrade_live.rs` for the resulting fixture
(`seed_metadata_true_up_fixture`, `synthetic_descriptor`, `wait_until_exclusive`,
`admit_one_reserved_spool_object`) and `run-cell-schema-forward-upgrade-live.ps1` for the dedicated
BLAKE3-capable container.

## CR-039 fragment-schema-upgrade fixture gotchas

Building a revision-4 clean-cell fixture by clean-initializing (reaching revision 6) then
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

**bb117070's backend-count guard refuses on this fixture file's own assertion connection.**
`upgrade_clean_schema` now calls `refuse_other_backends` (count `pg_stat_database.numbackends`
minus the coordinator's own pool size) before it even classifies the catalog -- so it fires on
*every* call, including a no-op `AlreadyCurrent` rerun. Every case in
`domain_fragment_schema_upgrade.rs` keeps its own `direct: Client` open across the whole test for
pre/post snapshots; left connected, that is itself "another backend" and the call refuses for the
wrong reason (backend-count, not the state the case means to exercise). Fix: drop `direct`
immediately before every `upgrade_clean_schema`/`assert_refused` call and reconnect fresh
afterward for post-call assertions -- see `call_upgrade`/`expect_upgraded`/
`assert_refused_dropping` in that file, mirroring `wait_until_exclusive` in
`lore-object-dispatch/tests/cell_schema_forward_upgrade_live.rs`. The guard's own bounded settle
loop (`BACKEND_SETTLE_ATTEMPTS`/`BACKEND_SETTLE_INTERVAL`, ~2s) absorbs an in-process drop's
async socket teardown, so a plain `drop` before the call is normally enough -- **except across a
separate OS process**: `lore-server/tests/fragment_schema_upgrade_operator.rs`'s real-binary rerun
needed an explicit poll-to-zero on `numbackends` (not just a `drop`) before launching the second
`loreserver` subprocess, because a 4-connection pool's teardown from the FIRST process's
perspective could outlast the coordinator's 2s budget as seen from the second process. Once ANY
second connection (lock or not) is enough for the count check to refuse first, the `NOWAIT`
table-lock backstop has **no remaining test that reaches it through an ordinary second
connection** -- `a_live_lock_holder_refuses_while_another_session_is_connected` (renamed from
`..._refuses_with_contention_not_a_wait`, which asserted only `matches!(.., Contention(_))` and so
silently stopped discriminating the two refusal paths) and
`a_realistic_row_exclusive_writer_refuses_while_another_session_is_connected` both now assert the
exact count-check message (`"other backend(s) are connected"`), naming what they actually prove.
The NOWAIT statement is still real and still matters as the documented race backstop (a
connection that lands between the count check passing and the `LOCK TABLE ... NOWAIT` call), but
that race is not exercised by any test in this file; reaching it would need a hook inside the
coordinator (a failpoint) that does not exist here, not a second plain connection.
An event-trigger fault injection (`CREATE EVENT TRIGGER ... ON ddl_command_start WHEN TAG IN
('ALTER TABLE')`, gated on `current_query() LIKE '%<a string unique to the target DDL>%'`) is a
reliable way to fail a specific statement mid-multi-statement-`batch_execute` without touching
production code; pair it with a positive control (`RAISE ... USING ERRCODE` on a throwaway
connection) proving the SQLSTATE the coordinator's own `pg()` wrapper is expected to surface.

## General Pitfalls

- **Hashing output for whitespace**: Hashing ignores `\r\n` vs `\n` normalization in pipelines. Use `SELECT position(chr(13) in prosrc)` or `.gitattributes` `eol=lf` limits instead.
- **Poisoning cache fields**: If you poison an in-memory `State`/`Tree` for a fault-injection, call `state.mark_dirty()` or it will not serialize.
- **Capturing LoreEvents**: Always drain to `LoreEvent::End`, not just the first event, as initial events might be non-terminal.
- **Agreement tests**: When two validators check the same field, test their agreement explicitly, not just rejection.
- **Negative controls**: A test asserting "no error" must have a companion positive control proving the success path is actually run.
- **Public stage concurrency**: Test multi-worker lifecycle with a Tokio multi-thread runtime.
- **Doc comments**: Module doc comments can trip source-pin scans if they name forbidden words. Use exact syntactical shapes instead.
- **Process-global state**: OTel, auth caches, etc., are shared. Avoid assertions on global emptiness.

## AWS SDK specifics

- Include explicit `ErrorMetadata.code(...)` for exceptions.
- Adaptive retry's rate limiter is shared. Keep `Standard` mode unless overridden. `Disabled` mode applies one attempt only.

## PowerShell live-test scripts

- **Argument arrays**: Build command arguments as an array (`$args = @(...)`) and use splatting (`& cmd @args`) instead of backticks.
- **Output truncation**: `Format-Table` truncates to console width; use `Out-String -Width 200`.
- **Line continuations**: `+` continues an expression, not a command. Assign to a variable first.
- **List diffs**: Cross-check hardcoded live-test targets against `cargo test --list`.
- **Piping to head**: `script | head` can SIGPIPE without killing detached containers. Redirect to files.
- **Container ownership**: Confirm container ownership (e.g. by pid label) before removal.

## Running Unix-only tests on Windows (Docker Desktop)

1. **Scratch copy**: Copy working tree to a scratch directory (`robocopy <repo> <scratch> /E /XD target .git`) to avoid read-only or concurrent mutation issues.
2. **Volumes**: Use named Docker volumes for `CARGO_TARGET_DIR` and the cargo registry cache.
3. **Environment**: Base image `rust:slim-trixie` needs `protobuf-compiler libprotobuf-dev build-essential`. Add `clippy` via rustup if needed.
4. **Execution**: Run detached, poll `docker inspect` for status, then remove.
5. **Fixture manifests**: If a test runs `cargo check --offline` on a fixture crate, prefetch it with `cargo fetch --manifest-path <fixture>/Cargo.toml` first.
6. **Port allocation**: Avoid `bind(0)` when both TCP and UDP ports are needed; Windows has disjoint UDP/TCP reservations. Sample randomly instead.
