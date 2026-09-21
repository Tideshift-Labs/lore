# Durable test patterns and gotchas: `tideshift/main`

Durable, recurring testing lessons grouped by topic.

## Build and merge hygiene

- **Rebuild test targets after merge**: Signature changes might not break `cargo build` but can break `cargo test`.
- **Incremental state issues**: If untouched files report impossible errors, clean the affected crate.
- **Timing-sensitive tests**: Rerun failures in isolation; they might be scheduling flakes under load.
- **Protobufs**: Regenerate instead of hand-splicing. Box large `prost` oneofs to avoid large enum variants and pin the boxed shapes.
- **Clippy**: Check crate-local `clippy.toml` which shadows workspace configs.

## Deterministic async tests

- **Time pausing**: `#[tokio::test(start_paused = true)]` doesn't work well with cross-thread I/O (`lore_io::IoDriver`) or tasks spawned on the global `lore_base::runtime::runtime()`. Use unpaused clocks with real margins for these.
- **Zero-retry policies**: Use near-zero retries for behavioral tests to avoid artificial delays.
- **Lifecycle callbacks**: Use `FileStageEnd` to remove an Add; use `FragmentWrite` to mutate working bytes to ensure immutable capture behavior.
- **Rejections**: Follow rejected exact-selection attempts with sequential-retry cases to ensure no stale metadata is left in memory.
- **UTF-8 limits**: Test exact byte boundaries and one byte over. Include sparse binary sources to test open-once read caps.
- **Timeouts**: Wrap stream assertions in `tokio::time::timeout`. Bind ephemeral ports once to avoid readiness races.

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
