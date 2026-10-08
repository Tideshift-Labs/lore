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

- Upstream crates with `[lib] test = false` (lore-server, lore-revision, lore, lore-transport,
  lore-base, lore-storage and the other upstream crates) keep unit tests in one `tests/unit/`
  binary per crate, where the crate has unit tests. Run `cargo test -p <crate> --test unit`. A test's name drops the old
  `tests::` segment: `plugins::postgres::tests::x` is now `plugins::postgres::x`. Private items
  are reached through the crate's `test-util` feature. `scripts/test/test_unit_test_layout.py`
  fails if such a crate keeps a `#[cfg(test)]` under `src/`.
  Fork tests in these crates follow the same layout: put them in `tests/unit/<module path>.rs` and expose the private item with `#[lore_macro::test_pub]` (public under `test-util`). Do not add a `#[cfg(test)]` module to `src/`; the gate matches comments too, so reword doc comments that quote it. Run the gate with `uv run pytest scripts/test/test_unit_test_layout.py`.
- The fork-only crates (lore-postgres, lore-object-dispatch, lore-fragment-provider) still keep
  crate-local `#[cfg(test)]` modules. Run `cargo test -p <crate> --lib`.
- Integration tests live under each crate's `tests/` and in `lore-integration-tests`.
- Infrastructure-gated Postgres/S3 tests are `#[ignore]`; run them with `-- --ignored` and the
  documented environment variables. An unset environment must never report an infra test as passed.
- **Always run `cargo` with the working directory inside `lore/`.** `.cargo/config.toml` is resolved
  from the CWD, never from `--manifest-path`, so `cargo test --manifest-path <lore>/Cargo.toml -p
  lore-server` from a parent directory silently drops `--cfg tokio_unstable` and `--cfg
  uuid_unstable`. Symptom is a compile cascade in files you never touched — `unresolved import
  crate::telemetry::OtelTokioRuntimeMetrics` ("found an item that was configured out") plus `Uuid:
  IntoBytes/FromBytes/Immutable is not satisfied` at
  `lore-server/src/protocol/replication_store/header.rs:10`. Do not read that as another lane's
  in-flight edit; `Set-Location <lore>` first and rebuild.
- After a conflict-heavy merge, build affected test targets before interpreting individual failures.
  Then run formatting and warnings-as-errors Clippy on the affected crates.

Baseline gates for a substantial fork merge:

```text
cargo +nightly fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --no-deps -- -D warnings
cargo test --workspace --no-fail-fast -j 4
```

- `--no-fail-fast` is required: without it the first failing crate stops the run and hides the rest.
- `lore-integration-tests` fixtures resolve `../../lorehub/docker/test-fixtures`, so they assume the
  `lorehub-all` sibling layout.
- `scripts/test` needs `--use-grpc` on the fork.

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

See [`testing-fork-delta-inventory.md`](testing-fork-delta-inventory.md) for the per-module map
from our fork's deltas to their most useful automated gates.

## Durable test patterns and gotchas

See [`testing-gotchas.md`](testing-gotchas.md) for recurring, durable testing lessons grouped by
topic.

## Appending new findings

Add only lessons likely to recur, and keep each entry short:

- A fork delta and the gate it needs → [`testing-fork-delta-inventory.md`](testing-fork-delta-inventory.md), grouped under the closest existing entry.
- A durable, recurring testing lesson not tied to one delta → [`testing-gotchas.md`](testing-gotchas.md), grouped under the closest section.

Chronology, command transcripts, and one-off reviewer narratives belong in `docs/worklogs/`.
