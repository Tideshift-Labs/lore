# Durable test patterns and gotchas: `tideshift/main`

Split out of [`testing-guide.md`](testing-guide.md) on 2026-09-11 to keep the orientation guide
short; nothing below was edited, only relocated. Durable, recurring testing lessons grouped by
topic — chronological execution notes belong in `docs/worklogs/`.

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
  `false` for clarity. Same drift recurred (2026-08-30): `GrpcServerBuilder::with_lock_store` now
  returns `GrpcServerBuilder<MaybeDomainContext>` (CR-029), which needs `.with_domain_context(None)`
  before `.with_notification(..)` compiles; `remote_store_test.rs`, `storage_copy_on_write_test.rs`,
  and `storage_remote_test.rs` are all stale against it as of this writing. Because
  `lore-integration-tests` sets `autotests = false` and pulls every `tests/*.rs` into ONE
  `[[test]] name = "integration"` binary via `mod`, a stale file anywhere blocks
  `cargo test -p lore-integration-tests --features integration_tests` for every file, including a
  brand-new one added correctly. To verify your own new file in isolation without touching files
  you don't own: temporarily comment out the offending `mod` lines in `tests/integration.rs`, run,
  then restore the file exactly (`git diff` should show only your intended lines) before finishing.
- If an untouched file reports an impossible macro/import/rlib error after alternating Clippy and
  test builds, suspect stale incremental state. Clean only the affected crate before escalating.
- **A timing-sensitive test can FAIL only inside a whole-crate `cargo test -p <crate>` run and PASS
  when its own file is run alone**, under heavy multi-lane shared-checkout build contention (many
  concurrent `cargo`/`rustc` processes queued on the same `target/` lock). Observed 2026-09-16:
  `lore-object-dispatch`'s `tests/shared_dispatch_pool.rs`
  (`ambiguous_commit_and_dead_sessions_poison_while_retry_sleep_follows_release`,
  `outer_charge_timeout_distinguishes_precommit_from_commit_started_and_retires_the_session`, both
  sleep/timeout-classification cases) failed once in a full `cargo test -p lore-object-dispatch`
  and passed cleanly on an immediate isolated rerun (`cargo test -p lore-object-dispatch --test
  shared_dispatch_pool`). Before treating this shape as a regression: rerun the one failing test
  binary alone; a pass there under load is a scheduling flake, not new evidence about the code.
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
  Unsound when the awaited work is real cross-thread I/O (`lore_io::IoDriver`), not a pure timer —
  `tokio::time::timeout` reported the full budget elapsed regardless of actual outcome (revert-
  checked: a comparison broken to resolve on the first check still took the full 10ms), because
  paused-clock auto-advance races ahead of the real I/O completion. Use the real, unpaused clock
  instead against the function's own small budget — `state.rs`'s `wait_until_settled_*` tests.
- `lore_base::lore_spawn!`'s no-joinset form spawns onto `lore_base::runtime::runtime()` — a
  separate, lazily-built, process-wide Tokio runtime (`lore-base/src/runtime.rs`), not the calling
  `#[tokio::test]`'s own runtime. Pausing time is scoped to the runtime that owns the time driver
  a task is polled on; pausing the test's runtime does not pause, slow, or synchronize with a
  `tokio::time::sleep` inside a `lore_spawn!`-spawned task, which keeps running on the real clock
  regardless. Worse than merely "no speedup": if the *test* task also reads
  `tokio::time::Instant::now()`/`.elapsed()` around waiting on that spawned task (e.g. to observe
  how long an admission queue took), pausing the test's own clock makes that measurement compute
  against the frozen virtual clock while the real wait genuinely elapses elsewhere — reporting
  ~0ms elapsed no matter how long the spawned task actually held something. Same failure shape as
  the `IoDriver` case above, different cause (cross-runtime dispatch, not cross-thread I/O). Only
  pause a test whose entire awaited chain resolves on the same runtime with no `lore_spawn!`/
  `lore_spawn_net!`/`lore_spawn_core!` in it; otherwise keep a real clock and a margin wide enough
  that ordinary scheduler jitter can't plausibly close it (`lore-fragment-provider/src/lib.rs`'s
  `a_charge_carrying_attempts_deadline_survives_the_admission_queue` widened from a ~150ms hold
  with a 100ms margin to a 400ms hold with the same 100ms margin, rather than pausing).
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
- A thin wrapper delegating to a shared inner impl needs a test calling the wrapper itself, not the
  inner fn through another caller — a merge can drop/replace one delegated argument at just that
  call site. Observe the caller-owned output's effect end-to-end, not just that the call returned
  `Ok` (`commit.rs`'s `commit_files_and_rehash_wrapper_forwards_callers_modified_times`).
- A cross-repo fixture path (`CARGO_MANIFEST_DIR/../../lorehub/...`) hard-fails a standalone
  checkout with no sibling `lorehub` (an upstream contributor's clone, or a fork clone without
  `lorehub` beside it) even though the "must FAIL, never skip" convention is correct for OUR
  workspace, where the sibling is always present. Distinguish the two facts by probing the sibling
  **repo root directory**, not the fixture file: root absent -> print one loud notice and return
  early (skip only this environment shape); root present but the named fixture missing/unreadable
  -> panic exactly as before (real drift in our own workspace, so this branch is the only one our
  own CI ever takes and costs zero coverage here). An env override
  (`LORE_NOTIFICATION_PLANE_FIXTURES`) that fails to resolve is always a panic, never a skip — an
  explicit request deserves an error. Put the resolver in one `tests/common/*.rs` file per crate
  (`#[path = "common/fixture_resolution.rs"] mod fixture_resolution;` in each consuming
  `tests/*.rs`, the same per-file `#[path]` convention `case_namespace.rs` already uses — cargo
  autodiscovers each top-level `tests/*.rs` as its own binary, so this costs no shared-aggregator
  edit other lanes are touching). Because a `#[test]` fn can't return a "skipped" status (no
  runtime skip in libtest, only pre-declared `#[ignore]`), a helper that loads the fixture must
  return `Option<Value>` and every direct call site becomes `let Some(x) = load_fixture(...) else
  { return };` — a positive test's own "pass" therefore doesn't distinguish ran-for-real from
  skipped-with-notice by exit code alone; grep stdout for the printed `SKIP <test_name>:` line to
  tell them apart. Proven both ways rather than assumed: pointing the override at a temp directory
  of copied fixtures reproduces the full green suite; pointing it at an empty temp directory
  reproduces the exact same panic site/message as fixture drift, at `remote_notification_conformance.rs:78:29`
  in this repro (`error: os error 2`) — a `.is_dir()` check on the resolved directory alone is not
  enough, because an override can validly resolve to an existing-but-empty directory and must still
  fail on the specific missing file, not silently succeed. See
  `lore-server/tests/common/fixture_resolution.rs` and `lore-postgres/tests/common/fixture_resolution.rs`
  (WP-111 residual, 2026-09-15).
- To pin a "store only after X succeeds" ordering property through a realistic pipeline with many
  unrelated store calls first, fault-inject by key identity (computed ahead via its own public
  derivation), not ordinal call number, which only works for a fully enumerated narrow sequence.
- To stand in for a real-process condition a black-box live harness cannot organically induce (a
  receiver generation dying while holding an unresolved blocker; a self-contradictory checkpoint
  report), call the exact production write path directly against the shared database
  (`lore_postgres::domain::outbox::report_checkpoint`, not raw SQL) under the real process's own
  identity/generation/membership-version, rather than fabricating a row. This exercises the real
  fences (stale-generation, retired-generation, frontier-monotonicity) the same way a live caller
  would, and keeps the harness honest about what it actually observed vs. what it injected -- every
  case using this documents which fact is real and which is stood in for, in the case's own doc
  comment. See cases K and L in
  `lore-integration-tests/tests/active_active_two_process_test.rs` and
  `SharedBackend::report_synthetic_checkpoint`.

### A live `lore-postgres` test's bootstrap DDL has a 250ms bound, which a heavily loaded host can trip on its own

Symptom: `PostgresDomainStore::connect`/`PostgresImmutableStore::connect` fails with `"postgres
bounded schema DDL failed"`, SQLSTATE `57014` ("canceling statement due to statement timeout" or
"... due to user request"), on a *freshly created, idle* disposable Postgres container --
`docker stats` shows near-zero CPU on the Postgres container itself, and recreating the container
from scratch does not fix it. Cause: `pool.rs`'s `ensure_schema` sets `SET LOCAL statement_timeout
= '250ms'` before its bootstrap DDL (deliberately tight, to fail fast on a stuck migration rather
than hang) -- and 250ms is not a generous bound on a host with many concurrent `cargo`/`docker`
builds contending for CPU and disk (the same host-wide contention this guide's other entries
describe, e.g. 14-minute `cargo test` builds from lock contention alone). This is environmental,
not a code defect: reproduced 4/4 times in one session against both a reused and a freshly
recreated container, ruling out a stuck advisory lock. What to do: don't chase it as a bug: retry
once host load visibly drops (check sibling lanes' activity, or just wait), and don't read it as
"my test/code is broken" without first checking `docker stats` shows the Postgres container itself
idle. Worth knowing before spending time on lock-based theories, which look plausible (`pool.rs`'s
own `SCHEMA_LOCK_KEY`/`pg_advisory_xact_lock` is real) but do not explain a failure that a fresh
container reproduces identically.

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
not independent confirmation that a failure pre-existed. Concretely: this rig's global
`core.autocrlf=true` plus no `*.rs` rule in `.gitattributes` means `git worktree add` writes CRLF
`.rs` while the main checkout holds LF, so every `include_str!` source-text assertion spanning a
newline fails in the worktree only. Create it, or re-checkout into it, with
`git -c core.autocrlf=false`; `checkout-index -f` alone will not rewrite a file whose stat still
matches, so delete the tree first.

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

### A source-pin's own module doc comment can trip its own scan

A `mod.rs`-level doc comment explaining *why* a rule holds often quotes the forbidden words in
prose ("no type here names a `Pool`, a `Transaction`, or a connection checkout"). Scan for the
narrowest *call/type shape* that could not appear in that prose (`.transaction()`, `pool.get(`,
`deadpool_postgres::`), never a bare capitalized word — same convention as the existing
`fragment_write_claim_source_pins.rs`. See `lore-postgres/tests/write_behind_source_pins.rs`
(WP-114 CD-6/CD-7).

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
  console width, narrower for a redirected `pwsh -File` run than an interactive terminal -- a
  results table can silently drop its rightmost columns. Pin a width: `Out-String -Width 200`.
- A trailing `+` at end-of-line only continues an *expression* (`$x = "a" +`\n`"b"`). A cmdlet in
  command syntax parses `+` and the following string as two more positional arguments, not
  concatenation. Fix: assign the concatenation to a variable first (expression context), then pass
  that to the cmdlet.
- Cross-check a runner's hardcoded live-test name/target map against ground truth before trusting
  it: `cargo test -p <crate> -- --ignored --list` needs no infrastructure and enumerates every
  `<name>: test` line per target. Diff both directions as a hard error, not a warning -- every
  hardcoded entry must appear in the list (catches a rename) and vice versa (catches an unnoticed
  new live test). A `#[cfg(target_os = "linux")]`-gated test is unenumerable on a non-Linux rig, so
  a runner must name it NOT RUN from static source knowledge, not from this catalog.
- Piping a long-running provisioning script through `head` can `SIGPIPE` it mid-run without killing
  the underlying process tree -- a detached child (`pwsh.exe` driving Docker) can keep running
  unobserved, still holding a labelled container open. Redirect to a file instead.
- A container label restating only its own name/GUID proves self-consistency, not ownership -- true
  for any correctly running instance. Before removing a container you did not just create, get an
  independent ownership signal (e.g. an owning-pid label) and confirm that pid is dead.

### Known tier limitations

- Flat handler fixtures do not run the full commit rollup pipeline, so aggregate tree size can remain
  zero even when per-node sizes are real. Assert aggregate plumbing there and use integration tests
  for the real rollup.
- A local-only fixture may be unable to observe an error after remote fallback normalization. Test
  the integrity consequence as well: whether referenced addresses silently disappear from an `Ok`
  result.
- Runtime-specific I/O backends and real QUIC drain behavior remain platform/live tiers; record the
  omission rather than representing a portable unit run as full coverage.
- The `active_active_two_process` live harness has no seam to make a single JetStream durable
  consumer skip a delivery (no receiver-side failpoint exists; `LORE_FRAGMENT_FAILPOINTS` only
  reaches the outbox claim/accept sites), so a genuine broker-sequence gap in a live receiver's own
  `AckFrontier` is not producible there today. Case L
  (`case_l_an_unresolved_gap_blocks_the_frontier_and_cannot_be_skipped`) proves the checkpoint
  store's own refusal of a self-contradictory report instead, and says so in its doc comment --
  don't read a future green run of it as evidence a live gap was ever observed.
- A Unix-only module's platform gate can block its own *unit*-level tests, not only its crash/live
  tiers. `lore-postgres/src/store/write_behind`'s `ConfinedRoot::open` refuses off-Unix
  (`WriteBehindError::UnsupportedPlatform`), so on a Windows dev rig `#![cfg(unix)]`-gated
  functional tests against it are absent from the build (correctly — `cfg`, not `#[ignore]`, since
  this is a platform gate, not an infra gate). Docker Desktop's Linux engine is available on this
  rig, though, so treat this as "needs a Linux run", not REQUIRED-DEFERRED by default — see the
  recipe below. Only cross-platform text-scan pins (source-pin style) run on Windows for such a
  module without one.

### Running a Unix-only fork crate's tests from the Windows dev rig

`docker info --format '{{.OSType}}'` reporting `linux` means Docker Desktop's Linux engine is
already available — no WSL Rust toolchain install needed. Recipe, proven 2026-09-16 against
`lore-postgres --test write_behind_stage` (10/10 passed, container exit 0):

1. **Copy the working tree to a scratch directory first; do not bind-mount the live checkout
   read-write.** `lore-proto`'s build script writes generated output back into its own source
   directory (not just `OUT_DIR`), so a read-only bind mount fails the build
   (`Os { code: 30, kind: ReadOnlyFilesystem }` on `lore-proto`'s build script) and a read-write
   bind mount risks a container process touching files a sibling lane is mid-edit on in a shared
   checkout. `robocopy <repo> <scratch> /E /XD target .git` (exclude the disk-hungry `target/` and
   `.git/`) gives an isolated, disposable copy that still carries every *uncommitted* file — needed,
   since the interesting state during a multi-lane run is usually not committed yet.
2. Bind-mount that scratch copy read-write, and send `CARGO_TARGET_DIR` and the cargo registry
   cache to **named Docker volumes**, not the bind mount, so a Linux build's artifacts never land
   in the Windows `target/` another process might be reading.
3. Base image `rust:slim-trixie` (same as `lore-server/Dockerfile`) plus `apt-get install -y
   protobuf-compiler libprotobuf-dev build-essential` — `lore-proto`'s `prost`/`tonic` build needs
   `protoc`, and on Debian trixie `protobuf-compiler` alone is not enough: the well-known types
   (`google/protobuf/timestamp.proto`, imported by `lock.proto`) ship in `libprotobuf-dev`'s
   `/usr/include`, and without it the build fails at `protoc failed:
   google/protobuf/timestamp.proto: File not found` (measured 2026-09-18). If the same image also
   needs to run `cargo clippy`, add `RUN rustup component add clippy` — `rust:slim-*` ships without
   the clippy component, so an unmodified image fails with `'cargo-clippy' is not installed for the
   toolchain` (also measured 2026-09-18). Full recipe with both fixes baked in:
   `lore-postgres/tests/run-write-behind-linux.ps1`.
4. First run compiles the full dependency graph from cold (~2 minutes for this crate's tree on this
   rig); the named volumes make a second run incremental.
5. Launch detached (`docker run -d --name ...`), poll `docker inspect --format
   '{{.State.Status}}'` in a bounded loop inside one tool call, `docker logs` once it exits,
   `docker inspect --format '{{.State.ExitCode}}'` to confirm 0 before trusting the log's "ok"
   lines, then `docker rm` — never run this in the foreground of a single tool call, it will
   exceed most timeouts on a cold cache.
6. **The `# allow-posix` escape hatch does not apply here and should not be reached for.** The
   command is `docker run ... sh -c "..."`; the workspace's POSIX-shell-blocking hook parses at
   *shell segment* granularity, splitting on `;`/`&&`/`|`/newlines, so a `sh -c "..."` argument
   embedded inside a **single-line** `docker run` invocation is just one quoted argument token, not
   a command position — permitted, correctly. The hook DOES trip if the same `docker run` is spread
   across PowerShell backtick-continued lines: it splits the raw command on literal `\n` before
   PowerShell's own continuation semantics apply, so a continued line beginning with `sh -c "..."`
   reads as its own top-level shell invocation and is denied. Keep this one command on one line.
7. **A test that shells out to `cargo check --offline` against a *fixture crate* needs its own
   prefetch — warming the workspace registry can never satisfy it.**
   `lore-fragment-provider`'s `direct_put_compile_fail` and `drain_capability_compile_fail` are not
   trybuild targets (this workspace has no trybuild dependency). Each runs `cargo check --offline
   --manifest-path lore-object-dispatch/tests/compile_fail/get_only_rejects_metered/Cargo.toml` and
   asserts on the rustc diagnostic. That fixture is a separate crate with its **own checked-in
   `Cargo.lock`**, resolved independently of the workspace, so the versions the nested check demands
   are ones no workspace build ever downloads — a cold-vs-warm `CARGO_HOME` volume is simply the
   wrong axis, and `attempting to make an HTTP request, but --offline was specified` naming
   `aho-corasick`/`anyhow` is a *different dependency graph*, not a cache miss. Three attempts read
   it as cache warmth and concluded it was unfixable. One network-enabled, fixture-scoped command
   fixes it, with no source change:

   ```
   cargo fetch --manifest-path lore-object-dispatch/tests/compile_fail/get_only_rejects_metered/Cargo.toml
   ```

   `cargo fetch` honours that manifest's own lockfile, so `$CARGO_HOME` then holds exactly what the
   nested `--offline` check asks for. With it, both targets pass in the container: each
   1 passed / 0 failed / 0 ignored, exit 0 (measured 2026-09-18, `rust:slim-trixie`). Wired into
   `run-write-behind-linux.ps1`'s `-IncludeCompileFail` block, which stays opt-in because the
   prefetch needs network and nothing else in that runner does. Generalize the rule: before blaming
   an offline nested build on cache warmth, check whether the manifest it targets resolves against
   the workspace lockfile at all.
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

