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

See `lore-object-dispatch/tests/cell_schema_forward_upgrade_live.rs` for the resulting fixture
(`seed_metadata_true_up_fixture`, `synthetic_descriptor`, `wait_until_exclusive`) and
`run-cell-schema-forward-upgrade-live.ps1` for the dedicated BLAKE3-capable container.

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
