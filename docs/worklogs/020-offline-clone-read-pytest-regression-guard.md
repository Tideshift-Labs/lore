# Add a regression guard for offline-readability of a fresh clone (WP-105 follow-on)

**Date:** 2026-08-11
**Status:** Done; fork gates green, committed to `tideshift/main`. Not pushed.
**Classification:** [CLIENT] surface (drives the stock `lore` CLI end to end) but test-only — no
Rust changed, no shippable client code, zero divergence risk.

## Summary

018 and 019 fixed the WP-105 offline-clone break and its diagnosability gap, but neither left a
test in this repo pinning the actual user-facing invariant: *a fresh clone is readable offline*.
That gap is why the break shipped unnoticed and was only caught days later by
`lorehub-desktop`'s slow cross-repo full-stack WebDriver tier. This chunk closes it with one new
pytest file, `scripts/test/test_clone_offline_read.py` — no test-specialist dispatched, by
design: the test *is* the deliverable, so this session owned it end to end rather than handing
off.

## What changed

- `scripts/test/test_clone_offline_read.py` (new, ~150 lines incl. a long module docstring):
  - `test_fresh_clone_offline_status_reads_revision_state` — `status --offline --json` on a
    never-read clone emits exactly one `repositoryStatusRevision` whose `revision` equals the
    pushed tip.
  - `test_fresh_clone_offline_revision_info_delta_lists_files` — `revision info --delta --offline
    --json` emits the tip's `revisionInfo`, no `error` event, and a `revisionInfoDelta` set
    exactly equal to `{edited.txt, added.txt}`.
  - Design choices baked into the fixture: the clone is read offline *first* (any online read
    repopulates the local store and masks the bug, since retention is history-dependent
    post-WP-105); the expected tip signature is read from the source repo, never the clone; the
    asserted revision deliberately carries no DELETE row (see Findings below).
- No Rust changed. `Cargo.toml` shows modified but is the pre-existing local profile tweak noted
  in 018/019, not staged, not part of this chunk.

## Why now

018's fix and 019's diagnosability improvement both landed without a test proving the end-to-end
property they restore. An AST scan of all ~40 files in `scripts/test/` found five call sites that
do an offline read on a clone-derived repo (`test_view.py:227`, `test_revision_list.py:42,47`,
`test_metadata.py:173`, `test_branch.py:1405`), but none is a fresh-clone offline-readability
check — the closest, `test_view.py`, reads a view-filtered clone only *after* online reads have
already populated it.

## Revert-check matrix

Each row is a real `cargo build --release --bin lore`, then a pytest run, then the revert
restored (`git diff` on `lore-storage/src/read.rs` and `lore-revision/src/state.rs` empty after
every row):

| Reverted | Result |
|---|---|
| retention disabled entirely (`always_retained` forced false) | BOTH tests RED, `Not found` at `state.rs:606`, status 13 — WP-105's exact symptom |
| `lore-storage/src/read.rs` back to keying only on `PayloadLocalCachePriority` | GREEN, does not reproduce |
| `lore-revision/src/state.rs`'s `State::tree` without `.with_cache().with_priority()` | GREEN, does not reproduce |
| gate on `PayloadRevisionState` alone (simulating the server allowlist strip) AND `State::tree` reverted | status test GREEN; delta test RED on the file-rows assertion, `complete.status` still 0, non-terminal `error` event present |

The two single reverts don't reproduce because this suite's `loreserver` runs
`immutable_store.mode = "local"` (filesystem store, preserves `PayloadLocalCachePriority`
end to end). WP-105's actual trigger — `lore-aws`/`lore-postgres`'s `PAYLOAD_FLAGS` allowlist
stripping that bit from the S3 object — cannot be produced by a local-store run; that's a
property of the topology, not test weakness. The last row reproduces the exact intermediate
state `f3213c6`'s message described, and is why the tests carry the file-rows and no-error
assertions rather than resting on exit code alone.

## Reviewer findings (`lore-reviewer`) — applied vs deferred

Applied:
1. Moved the `errors == []` assertion above the row assertions, so a real failure surfaces the
   error event's exact storage address instead of losing it to a row assertion firing first.
2. Added a docstring cross-reference to `lore-revision/tests/info.rs` as the library-level guard
   for the report-don't-swallow half.

Verified and not applied as written: flagged `revision history --offline` on a fresh clone as an
untested sibling. Measured it instead of adding a test for it — see Findings item 1.

Confirmed by the reviewer reading source, not taking the claim on faith: `errors == []` is
non-vacuous (`LoreEvent::Error` serializes as `tagName: "error"`, the CLI prints every event as
JSONL); the `flagFile` exact-set filter drops only directory rows; `Lore.clone()` issues no lore
command after cloning, so the clone really is unread.

## Findings worth recording

1. **`revision history --offline` on a fresh clone is broken today, on the fixed tree.**
   Measured: emits the tip `revisionHistoryEntry`, then terminates status 13, `Not found` at
   `state.rs:606:37` via `revision/history.rs:245` ("deserializing state") — a sparse clone holds
   the tip's state but not its ancestors'. Same hard-fail-vs-report asymmetry `c0d4a60` (019)
   fixed for `revision info`, not yet applied to `history`. Not pinned by a test here —
   asserting today's hard-fail would cement behavior we likely want to change. Flagging as an
   open follow-up.
2. **A DELETE row at the tip makes `revision info --delta --offline` hard-fail** on a fresh
   clone (add row emitted, then status 13 `Not found` at `state.rs:606` via `info.rs`
   "deserializing state" — it needs the parent revision's state to recover the removed node's
   path). Expected sparse-clone behavior; confirms the residual noted in 018. This is why the
   fixture's tip deliberately carries no delete.
3. **The suite's port allocator is fragile on Windows.** `scripts/test/lore_server.py`'s
   `allocate_free_port` binds TCP `:0` then probes the same number for UDP, retrying 20 times.
   Windows' TCP ephemeral allocator walks sequentially, so once it enters a UDP exclusion band
   (this rig has ~19 excluded ranges in 49152-65535) all 20 attempts fail and the session errors
   out with `WinError 10013`. Hit twice, persistent rather than transient once inside the band.
   Worked around with explicit ports (`--lore-remote-quic-port 55000 --lore-remote-grpc-port
   55000 --lore-remote-http-port 55001 --lore-remote-internal-port 55002`). Worth fixing in the
   allocator (skip excluded ranges, or bind UDP first).
4. `docs/testing-guide.md` has no section on the Python suite at all, despite it being the only
   tier that drives the real CLI end to end.

## Verification

- Final green on the restored tree: 2 passed / 0 failed, 14.30s.
- Whole-suite `--collect-only`: 875 collected, 0 collection errors (873 baseline + these 2).
- `ruff check` + `ruff format --check` clean.
- Binaries rebuilt from `tideshift/main` `10e4e10` (`loreserver.exe` was stale from before the
  0.8.7 merge, so it was rebuilt too, not just `lore.exe`).
- No docker stack brought up — the pytest suite spawns its own loreserver.

No upstream PR — standing hold until production ships. Commits land in `lore/` only, with DCO
`Signed-off-by` + AI-authorship disclosure.
