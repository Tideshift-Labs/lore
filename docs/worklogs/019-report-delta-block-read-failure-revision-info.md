# Report a delta-block read failure from `revision info` instead of swallowing it

**Date:** 2026-08-11
**Status:** Done; fork gates green, live before/after proof green, `lorehub-desktop` full-stack
WebDriver tier re-run clean on 2026-08-11 (all four targets green — see Deferred item 1).
**Classification:** [CLIENT] (`lore-revision` ships in the CLI and links in-process into
`lorehub-desktop`).

## Summary

`revision::info` (`lore-revision/src/revision/info.rs`) wrapped its delta-block read in
`if let Ok(delta_buffer) = ...` with no `else` arm: a storage-layer read failure silently skipped
the per-file-change emission loop and `info()` still returned `Ok(())` with zero file rows — byte-
identical output to a revision that genuinely changed nothing. That swallow made a read failure look
like a data problem and cost WP-105 three days of misdiagnosis. It's the **second** recorded
occurrence: INV-AS1 logged the first (different underlying cause) and asked for exactly this fix
("the optional Lore CR from INV-AA — surface the `delta_block` error"); INV-BN §2 hit it again during
WP-105. Fixed by reporting the failure without propagating it: on `Err`, emit a mid-stream
non-terminal `LoreEvent::Error` via `execution_context().dispatcher.send_error(...)`, then fall
through to the unchanged `Ok` path. `info()` still returns `Ok(())`; the terminal status stays 0.

Tolerant-not-fatal is deliberate: a sparse clone legitimately lacks an ancestor's delta block when
read offline, and `lorehub-desktop`'s History view calls this path once per revision. Propagating
would trade a mildly-wrong file list for a fully broken view. The premise that makes an unconditional
report correct: a revision that changed nothing carries a zero `hash_delta`, which short-circuits to
`Ok(empty)` with no error (`lore-storage/src/read.rs:223-225`, `:457-459`), so every `Err` reaching
the call site is already a real failure — verified from source before designing, now pinned by a
`#[cfg(test)]` test in `read.rs`.

## What changed

- `lore-revision/src/revision/info.rs` — the fix, entirely inside `pub async fn info` (33
  insertions / 3 deletions). Error message reworded to "the revision delta could not be read"
  (deliberately names no specific block — see Reviewer findings) with a comment explaining why.
- `lore-revision/tests/info.rs` — new, 3 tests: the failure-reports-error guard, a zero-`hash_delta`
  negative control (no error, no rows), and a healthy-revision positive control. Post-review, their
  shared `drain_events` helper was fixed to drain to `End`.
- `lore-storage/src/read.rs` — one added `#[cfg(test)]` test pinning the zero-`hash_delta` premise;
  no production change.
- `docs/testing-guide.md` — test-specialist upsert, two durable lessons (see below).
- `Cargo.toml` shows modified but is a pre-existing local profile tweak unrelated to this chunk, not
  staged.

## Why now

Two independent investigations (INV-AS1, then INV-BN during WP-105) hit the same swallow and the
first explicitly asked for this exact fix. Diagnosability is the whole point of the change, so it
was worth getting the message content right too (see below) rather than just adding a signal.

## Reviewer findings — applied vs deferred

`lore-reviewer`, classification [CLIENT]. No LEP needed — `LoreEvent::Error` is already documented
as non-fatal for `info` (`lore/src/revision.rs:308`).

Applied:
1. The error message named the wrong subsystem. `State::delta_block` awaits `State::tree` first, so
   a TREE-block failure lands in the same `Err` arm — confirmed by the live repro below, where the
   deleted block was actually the tree block while the message said "delta block". Reworded to name
   no specific block, with a comment explaining why; the underlying error still carries the exact
   address.
2. Two test gaps (drain-to-first-event weakness, missing success-path pin) — fixed and revert-checked,
   see below.

Verified-and-not-applied: reviewer predicted the message would double a clause ("...could not be
read: Failed to deserialize delta block: ..."). Live run showed no doubling — `Internal`'s `Display`
delegates to its source, so that context lands on the trace, not the message. Refuted by execution,
not accepted on plausibility.

Noted as a contract change, for the eventual upstream PR body: `--json` routes `revision info`
through `output_formatter()`, so JSON mode now emits two extra records (`log`, `error`) before
`complete`, with `complete.status` still 0. Live-verified with both binaries. Grepped every
first-party consumer (`lorehub/scripts`, `lorehub-desktop/scripts`, `src-tauri/src`, `crates/`,
`e2e/`, `commit0-unreal`): none parses `lore ... --json`, so nothing we own breaks today.

## Test-specialist findings worth recording

Its first pass had two false-green shapes in its own tests, found by the reviewer, then fixed and
revert-checked RED against the pre-change code:
- `drain_events` returned on the FIRST event, and `info()` always sends `RevisionInfo` first — so
  the failure-guard test could pass before the `Error` event arrived (latent flake), and the negative
  control's `error_count == 0` was near-vacuous. Now drains to `LoreEvent::End`.
- Nothing pinned the success path, so an impl that emitted the error event AND skipped the delta
  loop would still have passed. Added `healthy_revision_reports_delta_rows_and_no_error_event`.

## Verification

- `cargo +nightly fmt --all -- --check` clean; `cargo clippy --all-targets -p lore-revision
  -p lore-storage -- -D warnings --no-deps` clean.
- `cargo test -p lore-revision -j 4`: 631 passed / 0 failed / 1 ignored (baseline 628/0/1, +3 new).
- `cargo test -p lore-storage -j 4`: 216 passed / 0 failed (baseline 215, +1 premise pin).
- `cargo build --release --bin lore`: Finished.
- `lorehub-desktop` Rust tier (`bun run test:rust`, src-tauri + lore-engine + commit0-cli, built
  against this lore): 2798 passed / 0 failed / 55 ignored across 59 result lines.
- Live before/after on an isolated `--lane test` stack (never slot 0/50, `down -v` after). Two
  binaries actually built (change stashed, rebuilt, saved as `lore-before.exe`) — a real comparison.
  Repo seeded on loreserver, 2 commits, pushed, fresh clone; revision-2 TREE block `a22f9974…`
  (which gates the delta read) deleted from two copies:
  - BEFORE `revision info --delta --offline @2`: header, blank file list, exit 0, silent stderr.
  - AFTER, same command: `[Error] no file changes are being reported for revision 27176a12…: the
    revision delta could not be read: Address not found: a22f9974…` on stderr, header still renders,
    exit still 0.
  - Negative controls, both silent as required: healthy clone offline (renders the two changed
    files); damaged clone read ONLINE (remote refetch repairs it, no false alarm).
- Original (pre-fix) test re-run by hand and confirmed failing with
  `expected a LoreEvent::Error naming revision …, got []` — the swallow's exact symptom.

## Deferred / follow-ups

1. ~~**`lorehub-desktop`'s full-stack WebDriver tier was not run — required-deferred, not skipped, not
   passed.**~~ **RESOLVED 2026-08-11: run clean, all four targets green.**
   `bun run test:webdriver:fullstack:managed` originally died in bring-up (`tsc && vite build`) on
   type errors in another agent's uncommitted WIP under
   `lorehub-desktop/src/components/shell/views/audit/`, so zero of the four targets ran. Once that
   work landed (`lorehub-desktop` `4903062`, `tsc --noEmit` clean) the main session re-ran the tier
   unmodified: `webdriver_fullstack`, `webdriver_fullstack_history`, `webdriver_fullstack_reviews`
   and `webdriver_fullstack_story` each **1 passed / 0 failed / 0 ignored**, runner banner
   `✓ PASS — all targets green`. This was the gate on the one real risk in this change — that
   reporting the failure could flip the desktop's History from a mildly wrong file list to an error
   state — and `webdriver_fullstack_history` explicitly reported "History rendered the full chain
   (tip + oldest ancestor) + expanded ancestor deltas, no read failure". The risk is closed by
   execution, not by the `code != 0` argument alone.
2. General lesson: a shared repo's uncommitted WIP can block an unrelated change's gate entirely. The
   correct response is to report the gate as not-run and defer it — never modify, stash, or revert
   someone else's working tree to green your own gate, and never quietly drop the gate.
3. `lore-revision/tests/commit.rs` (`commit_emits_revision_commit_event_on_success`,
   `commit_without_staged_changes_emits_no_commit_event`) has the same first-event-break drain
   weakness as the tests fixed here. Left out of scope; recorded so it isn't lost.
4. `lorehub-desktop` doesn't yet consume the new signal — `ErrorSink` captures the mid-stream reason
   and drops it whenever status is 0. Surfacing it (so History can distinguish "unreadable" from "no
   changes") is the natural next step and closes INV-AS1's obligation on the consumer side.
5. No desktop test pins the captured-and-dropped property this tolerance design depends on; it's
   enforced structurally by `if code != 0` at `crates/lore-engine/src/revision.rs:436-438`.

No upstream PR — standing hold until production ships (2026-07-25). Commits land in `lore/` only,
with DCO `Signed-off-by` + AI-authorship disclosure.
