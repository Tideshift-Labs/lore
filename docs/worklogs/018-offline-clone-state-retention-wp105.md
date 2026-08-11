# Fix offline-clone state-fragment retention lost in the 0.8.7 merge (WP-105)

**Date:** 2026-08-10
**Status:** Done; fork gates green, end-to-end proof green. Not yet committed (working tree has
the diff staged for review).
**Classification:** [CLIENT] (clone / local-store read path) — we still control the build, but this
follows the fork's client-path review discipline since it's on the local-store code path.

## Summary

Since the fork's upstream 0.8.7 integration (`8f8d358` + `8731ad5`), a fresh `lore clone` retained
no revision-state blocks in the workspace's local immutable store. Every offline read that
deserializes state failed (`--offline status`, `--offline revision info`, `--offline branch info`);
online reads silently fell back to remote fetch and hid it. `lorehub-desktop` drives
history/status/branch reads offline, so three of its full-stack WebDriver targets were red from
this one cause. Root cause: not a read-path change (`state.rs:605`'s deserializer, `revision/info.rs`,
`revision/history.rs` are byte-identical across the merge), but a server-side flag-persistence
change — the S3-authoritative `PAYLOAD_FLAGS` allowlist landed by the merge (`554e937`,
`lore-aws/src/store/object_metadata.rs:38-40`) deliberately excludes `PayloadLocalCachePriority` as
a per-machine hint, so the bit `load_fragment`'s cache gate keyed on stopped surviving the round
trip. Confirmed directly against a live MinIO object's `X-Amz-Meta-Lore-Fragment` metadata.

## What changed

- `lore-storage/src/read.rs` — `load_fragment`'s retention gate now also keys on
  `PayloadRevisionState` (an `always_retained` binding covering both flags), not just
  `PayloadLocalCachePriority`. `PayloadRevisionState` describes what the payload *is*, so it's not
  subject to the allowlist stripping the cache-priority hint.
- `lore-revision/src/state.rs` — `State::tree`'s read now calls `.with_cache().with_priority()`,
  matching the ~11 sibling revision-metadata reads in the same file. Needed because the retention
  fix alone still left `revision info --delta` returning zero file rows offline: the tree block
  gates the delta, node and path reads. Also added the missing personal SPDX line next to Epic's.
- `lore-revision/src/repository.rs` — doc-comment only, widening `disable_cache`'s stated contract
  to name the two independent retention paths (the always-cached state exemption, and per-call-site
  `with_cache` opt-in) rather than just the state-fragment exemption.
- `lore-integration-tests/src/{remote_store_test,storage_remote_test}.rs` — a regression test with a
  real negative control (flipping the gate back to the single-flag form fails exactly the new
  assertion, 35 others stay green), plus a pre-existing signature-drift fix: both files still called
  the pre-CR-018 one-arg `GrpcServerBuilder::with_jwt_verifier(None)`, invisible to a plain build
  because both sit behind the `integration_tests` feature gate.
- `Cargo.toml`, `docs/testing-guide.md` — supporting test-harness wiring and a guide note.

## Why now

Nothing in the deserialize/read path regressed; the contract it broke is documented twice in the
code and was only ever satisfied incidentally: `lore-revision/src/interface.rs:647-650` ("Without
this only state fragments and fragments flagged for local cache priority are retained") and the
pre-fix `repository.rs:354` comment ("except state fragments which are always cached"). The upstream
merge's S3-authoritative flag allowlist (`554e937`, adopting `fe4f4e5`'s `PAYLOAD_FLAGS`) never
included `PayloadLocalCachePriority` by design, since it's meant as a per-machine hint, not content
metadata — so the client-side gate that had been piggybacking on that bit silently stopped working
the moment fragments started round-tripping through the allowlisted server. A reader-side fix (key
on the flag that already survives, by design) was chosen over re-adding the bit to `PAYLOAD_FLAGS`
because fragments already pushed since the merge keep the stripped metadata forever; a server-side
fix would leave existing repos broken on clone.

## Reviewer / investigation findings

- Found by execution, not source reading: the read-path files were confirmed byte-identical across
  the merge with `git diff`; the actual break was only visible by inspecting the live MinIO object's
  metadata bits directly.
- INV-BN's Addendum 1 "by-number revision resolution is broken" is **not** a regression — a bare
  numeric CLI argument is parsed as a partial hex signature, not a revision number; `@2` / `main@2`
  resolve correctly at fork HEAD. Not a code change; librarian-scribe is correcting INV-BN's text.
- New behavioral property to be aware of: offline readability is now history-dependent — two clones
  with identical revision sets can answer differently offline depending on what was fetched while
  connected.
- Known residual, not fixed here: an offline delta containing a DELETE row still needs the parent
  revision's state and tree, which a sparse clone has no reason to hold.

## Verification

- Baseline confirmed broken before any edit, all three symptoms at the cited lines, against the
  isolated `lorehub-dataplane-test` lane.
- Final repro on a fresh clone, post-fix: offline `revision info --delta` exit 0 with real file rows
  (`M src`, `M README.md`, `A src/added.cpp`); offline `status` exit 0.
- `lorehub-desktop` `bun run test:webdriver:fullstack:managed`: all four targets green, 1
  passed / 0 failed / 0 ignored each — `webdriver_fullstack` (7.38s),
  `webdriver_fullstack_history` (8.26s), `webdriver_fullstack_reviews` (12.00s),
  `webdriver_fullstack_story` (16.22s).
- `cargo clippy --all-targets -p lore-revision -p lore-storage -- -D warnings --no-deps`: clean.
- `cargo test -p lore-revision`: 628 passed, 0 failed, 1 ignored across 45 binaries.
- `cargo test -p lore-storage`: 215 passed, 0 failed.
  `lore-integration-tests -- storage_remote_tests`: 36 passed, 0 failed.
  `lore-aws --lib object_metadata`: 12 passed, 0 failed.
- `cargo +nightly fmt` clean; `cargo build --release --bin lore` green.
- Scope note: `cargo test` was run `-p`-scoped, not workspace-wide. A run that passes
  `--features integration_tests` is red on 44 `lore-integration-tests` failures
  (`aws_store_test`/`dynamodb_test`/`locks_test`) that hard-fail with `ConnectionRefused` against
  absent MinIO/DynamoDB. **Corrected 2026-08-11: this is correct behaviour, not a defect, and the
  follow-up originally raised here is withdrawn.** The `integration_tests` feature is itself the
  opt-in gate — a default `cargo test -p lore-integration-tests` is 126 passed / 0 failed /
  1 ignored and never runs them — so passing the flag is asserting the infra is up, and
  `ConnectionRefused` is the honest answer. `#[ignore]`-ing them would convert an explicit
  opt-in-without-the-infra into a silent non-run.

## Follow-ups created

- `#[ignore]` the 44 infra-gated `lore-integration-tests` failures so a plain workspace `cargo test`
  reports green honestly (currently red for reasons unrelated to any change in this chunk).
- CR-022 (Postgres existence/readability split) was spun off separately during the same
  investigation (INV-BN) — not part of this fix, tracked on its own doc in `lorehub/`.

No upstream PR — standing hold until production ships (2026-07-25). Commits land in `lore/` only,
with DCO `Signed-off-by` + AI-authorship disclosure.
