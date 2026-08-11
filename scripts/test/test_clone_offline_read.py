# SPDX-FileCopyrightText: 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Offline readability of a freshly-cloned repository.

A clone that has never been read while connected must still answer the two
reads a user reaches for first: `status` and `revision info --delta`. Both
deserialize the tip revision's state block, so a workspace that fetched those
blocks from the remote and then discarded them can only be read online.

This is the regression guard for WP-105, where a fresh clone retained no
revision-state blocks at all and every offline read of it failed. Nothing in
this suite cloned and then read offline, so the break shipped and was caught
days later by a downstream repository's full-stack tier.

What these tests do and do not catch, measured by reverting the WP-105 fixes
one at a time and rebuilding (do not assume, re-measure if you change either):

- Retention removed entirely (`load_fragment`'s `always_retained` gate always
  false): BOTH tests fail, `Not found` at `state.rs:606`, status 13. That is
  WP-105's exact reported symptom.
- `lore-storage/src/read.rs` reverted to keying only on
  `PayloadLocalCachePriority`, or `State::tree` reverted to dropping
  `.with_cache().with_priority()`, each on its own: BOTH tests still PASS.
  Neither revert reproduces here, and that is a property of this suite's
  topology, not of the tests. `lore-server`'s default config runs
  `immutable_store.mode = "local"`, a filesystem store that preserves
  `PayloadLocalCachePriority` end to end. WP-105's actual trigger was
  `lore-aws`/`lore-postgres`'s `PAYLOAD_FLAGS` allowlist stripping that bit from
  the S3 object, which no local-store run can produce.
- Simulate that strip (gate on `PayloadRevisionState` alone) AND revert
  `State::tree`: the status test passes, and the delta test fails on the
  file-rows assertion with `complete.status` still 0 and a non-terminal `error`
  event present. That is the intermediate state WP-105's author described, and
  it is why the file-rows and no-error assertions carry the weight rather than
  the exit code.

The single-flag half of the fix is pinned instead by `lore-integration-tests`'s
`get_caches_locally_when_payload_has_revision_state_flag`, which hand-seeds a
fragment with the bit already stripped. The companion property, that a failed
delta read reports itself rather than returning silently, is pinned at the
library level by `lore-revision/tests/info.rs`.
"""

import logging

import pytest
from lore_parsers import parse_error_json, parse_jsonl

from lore import Lore

logger = logging.getLogger(__name__)

# Files seeded into the source repository. The revision under test is the tip,
# which carries one modify and one add. BASE_FILE is committed in the first
# revision and never touched again, so it must NOT appear in the tip's delta:
# that keeps the delta assertion an exact set rather than a lower bound.
BASE_FILE = "base.txt"
EDITED_FILE = "edited.txt"
ADDED_FILE = "added.txt"


def _seed_and_clone(new_lore_repo) -> tuple[Lore, str]:
    """Push two revisions, then clone. Returns the clone and the tip signature.

    The tip's delta is deliberately one modify plus one add, with no delete.
    A delete row makes `revision info --delta` deserialize the PARENT revision's
    state to recover the removed node's path (`lore-revision/src/revision/info.rs`,
    the `is_delete` branch), and a sparse clone has no reason to hold an
    ancestor's blocks. Measured on a fresh clone of a tip carrying one delete and
    one add: the add row is emitted, then the command fails outright with status
    13 `Not found` at `state.rs:606`, forwarded from `info.rs` as "deserializing
    state". That is a sparse clone answering honestly, not this regression, so
    asserting on it here would pin an unrelated behaviour.

    The clone is returned unread: the retention this guards is history-dependent
    (anything fetched while connected is kept), so any online read of the clone
    before the offline one would populate the local store and mask the bug.
    """
    repo: Lore = new_lore_repo()

    repo.write_commit_push(
        "Seed",
        {BASE_FILE: ["base\n"], EDITED_FILE: ["original\n"]},
    )
    repo.write_commit_push(
        "Edit one file and add another",
        {EDITED_FILE: ["original\nedited\n"], ADDED_FILE: ["added\n"]},
    )

    # Read the tip from the SOURCE repo, which is already fully populated.
    # Reading it from the clone is the thing under test, so it cannot be the
    # source of the expected value.
    source_entries = parse_jsonl(repo.revision_info(json=True), "revisionInfo")
    assert len(source_entries) == 1, (
        f"Expected one revisionInfo entry from the source repo, got {source_entries}"
    )
    tip_signature = source_entries[0]["revision"]

    return repo.clone(), tip_signature


@pytest.mark.smoke
def test_fresh_clone_offline_status_reads_revision_state(new_lore_repo):
    """`status --offline` on a never-read clone must resolve the tip revision.

    Before WP-105 this failed outright with `Not found` raised while
    deserializing state (`lore-revision/src/state.rs`), because the state
    blocks the clone fetched from the remote were discarded instead of
    retained. Asserting the reported revision, not just a zero exit, keeps the
    assertion on the state actually being read.
    """
    clone, tip_signature = _seed_and_clone(new_lore_repo)

    entries = parse_jsonl(
        clone.status(json=True, offline=True), "repositoryStatusRevision"
    )
    assert len(entries) == 1, (
        f"Expected exactly one repositoryStatusRevision entry from an offline "
        f"status of a fresh clone, got {entries}"
    )
    assert entries[0]["revision"] == tip_signature, (
        f"Offline status on a fresh clone reported revision "
        f"{entries[0]['revision']!r}, expected the pushed tip {tip_signature!r}"
    )


@pytest.mark.smoke
def test_fresh_clone_offline_revision_info_delta_lists_files(new_lore_repo):
    """`revision info --delta --offline` must list the tip's changed files.

    Two halves, and both matter. The command has to succeed, and it has to
    return the real file rows: the pre-WP-105 failure mode exited 0 with an
    empty file list, so an exit-code-only assertion passes straight through the
    bug. The tree block gates every delta, node and path read, so a workspace
    holding the state block but not the tree still answers zero rows here.

    A delta read that fails now also emits a non-terminal `LoreEvent::Error`
    while leaving the terminal status successful, so the healthy path must
    report no error event either.
    """
    clone, tip_signature = _seed_and_clone(new_lore_repo)

    output = clone.revision_info(delta=True, json=True, offline=True)

    info_entries = parse_jsonl(output, "revisionInfo")
    assert len(info_entries) == 1, (
        f"Expected exactly one revisionInfo entry, got {info_entries}"
    )
    assert info_entries[0]["revision"] == tip_signature, (
        f"Offline revision info on a fresh clone reported revision "
        f"{info_entries[0]['revision']!r}, expected the pushed tip "
        f"{tip_signature!r}"
    )

    # Assert this BEFORE the row assertions below. When the delta read fails,
    # the error event carries the exact storage address that could not be read,
    # which is the most useful thing to put in the failure message; letting a
    # row assertion fire first would throw that diagnostic away.
    errors = parse_error_json(output)
    assert errors == [], (
        f"Offline revision info --delta on a healthy fresh clone reported an "
        f"error event: {errors}"
    )

    delta_entries = parse_jsonl(output, "revisionInfoDelta")
    assert delta_entries, (
        "Offline revision info --delta on a fresh clone returned NO file rows. "
        "An empty delta is indistinguishable from a successful read of a "
        "revision that changed nothing, which is exactly how this regression "
        f"shipped unnoticed. Output:\n{output}"
    )

    changed_files = {entry["path"] for entry in delta_entries if entry.get("flagFile")}
    assert changed_files == {EDITED_FILE, ADDED_FILE}, (
        f"Offline revision info --delta listed {sorted(changed_files)}, "
        f"expected the tip's one modify and one add: "
        f"{sorted({EDITED_FILE, ADDED_FILE})}. Output:\n{output}"
    )
