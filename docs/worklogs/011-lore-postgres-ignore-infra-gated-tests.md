# lore-postgres: report infra-gated tests as ignored, not passed

**Date:** 2026-07-26
**Status:** Done (fork-side, merged locally into `tideshift/main`; not pushed or submitted upstream)
**Classification:** [SERVER]. `#[ignore]` attributes and doc comments on `lore-postgres` tests only
— no production code path changes.

## Summary

`lore-postgres/tests/{immutable_store,lock_store,mutable_store,concurrency}.rs` hold 18 tests gated
on live Postgres + S3 env (`LORE_TEST_PG_URL`, `LORE_TEST_S3_ENDPOINT`, `LORE_TEST_S3_BUCKET`). When
that env is unset each printed a notice and returned. Rust's test harness has no skip concept, so it
counted every one as **PASSED** — and output capture swallowed the notice — so
`cargo test -p lore-postgres` reported "18 passed" while asserting nothing about 18 code paths. They
are now `#[ignore]`d: the run reports *ignored*, never *passed*; `-- --ignored` runs them once the
env is set. The runtime env check stays, so an `--ignored` run without env still exits early rather
than failing confusingly.

## What changed

- `lore-postgres/tests/immutable_store.rs`: `#[ignore]` added to all gated tests; module doc rewritten
  to explain the attribute is load-bearing (the false-PASSED failure mode), not cosmetic.
- `lore-postgres/tests/{lock_store,mutable_store,concurrency}.rs`: same `#[ignore]` treatment.
- 4 files, +35/-4.

## Why now

This false green is why CR-016's Postgres query (worklog 010) reached staging having never once
executed. Two real defects in it were then found by hand rather than by this suite, both while
consuming that query from the Lorehub side:

- `now()` is `transaction_timestamp()`, pinned at BEGIN — a row written later in the same
  transaction reads as being in the *future*, yielding a negative age. Fixed with `clock_timestamp()`.
- `greatest(0, NULL)` is `0` in Postgres (`greatest`/`least` ignore nulls) — a clamp added for the
  first defect silently converted "never measured" into "measured just now", the exact false
  all-clear that column's null exists to prevent.

Neither was subtle once the query actually ran; both were invisible to `cargo check`, clippy, and the
suite that claimed to cover them.

## Verified both directions

- Plain `cargo test -p lore-postgres` → 18 **ignored**, 0 falsely passed.
- `cargo test -p lore-postgres -- --ignored` against live Postgres + MinIO (Docker, throwaway
  containers, torn down after) → all 18 pass — the first time this suite has actually executed.

## Companion change (different repo, cited not duplicated)

Container commit `f82db2b` (`lorehub-all` workspace `CLAUDE.md` + the `commit0-monitoring` skill)
generalizes the executable-check rule to cover code just *written*, not only code under
investigation, naming why it's easy to miss — a test that skips and a test that mocks report the
same green as a test that passes — plus a separate prevention for alert design (ask what a rule
reads at t=0, before the thing it watches has ever worked).

## Tests and gates

No gates beyond the two `cargo test -p lore-postgres` runs above; the change touches only `#[ignore]`
attributes and doc comments, no production code.

## Follow-ups

None opened. The remaining 17 infra-gated tests across the fork (if any exist outside
`lore-postgres`) weren't audited here — this chunk was scoped to the file CR-016 exposed.
