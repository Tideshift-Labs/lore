# Copyright 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""`lore commit <message> --exact-selection <file>` (fork-local CLI form of
`lore::revision::commit_exact_selection`).

These drive the real `lore` binary offline against a local repository, so they
cover the clap wiring and the handler's file/JSON handling. The transaction
semantics are covered by the `lore` crate's `exact_selection_transaction` tests.
"""

import hashlib
import json
import os
import subprocess

import pytest
from lore_parsers import parse_status_json

from lore import Lore


def _write(repo: Lore, path: str, text: str) -> None:
    # Bytes, not text mode: the selection pins the MD5 of the content, so no newline translation.
    with repo.open_file(path, "wb") as output_file:
        output_file.write(text.encode("utf-8"))


def _selection(files: list[dict]) -> dict:
    return {"files": files}


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _entry(path: str, action: str, source_hash: str | None) -> dict:
    # `sourceHash` is the MD5 of the file content; it is required for add and modify.
    return {
        "path": path,
        "expectedEffectiveAction": action,
        "sourceHash": source_hash,
        "fileMetadata": {"kind": "unchanged"},
    }


def _write_selection(repo: Lore, name: str, text: str) -> str:
    # Beside the repository, so the selection file is never itself a change.
    selection_path = os.path.join(os.path.dirname(repo.path), name)
    with open(selection_path, "w", encoding="utf-8") as selection_file:
        selection_file.write(text)
    return selection_path


def _commit_exact(
    repo: Lore, message: str, *args: str, global_args: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    """Runs the CLI directly so stdout and stderr stay separate and a failing
    exit code is returned rather than raised."""
    return subprocess.run(
        [
            repo.lore_executable_path,
            "--repository",
            repo.path,
            "--offline",
            *global_args,
            "commit",
            message,
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
        env=repo._subprocess_env(),
        cwd=repo.path,
    )


def _dirty_paths(repo: Lore) -> set[str]:
    entries = parse_status_json(repo.status(scan=True, json=True, offline=True))
    return {entry["path"].replace("\\", "/") for entry in entries}


def _history_length(repo: Lore) -> int:
    return len(repo.revision_history(offline=True))


@pytest.fixture
def repo_with_baseline(new_lore_repo):
    """A repository holding `modified.txt` and `untouched.txt` in one revision."""
    repo: Lore = new_lore_repo()
    _write(repo, "modified.txt", "original\n")
    _write(repo, "untouched.txt", "original\n")
    repo.stage(scan=True, offline=True)
    repo.commit("Baseline", offline=True)
    return repo


@pytest.mark.smoke
def test_exact_selection_commits_only_the_selected_files(repo_with_baseline):
    repo = repo_with_baseline
    before = _history_length(repo)

    _write(repo, "added.txt", "new file\n")
    _write(repo, "modified.txt", "changed\n")
    _write(repo, "untouched.txt", "also changed, but not selected\n")
    selection = _write_selection(
        repo,
        "selection.json",
        json.dumps(
            _selection(
                [
                    _entry("added.txt", "add", _md5("new file\n")),
                    _entry("modified.txt", "modify", _md5("changed\n")),
                ]
            )
        ),
    )

    result = _commit_exact(repo, "Exact commit", "--exact-selection", selection)

    assert result.returncode == 0, result.stderr
    # The default event callback prints a progress line ("Fragmenting files ...") to stdout
    # ahead of the result, so the JSON object is the stdout from its first brace.
    payload = json.loads(result.stdout[result.stdout.index("{") :])
    assert payload["revision"]
    effective = {row["path"]: row["action"] for row in payload["effectiveActions"]}
    assert effective == {"added.txt": "add", "modified.txt": "modify"}

    assert _history_length(repo) == before + 1
    assert repo.revision_info(offline=True).message == "Exact commit"
    # The unselected modification is still pending.
    assert _dirty_paths(repo) == {"untouched.txt"}


@pytest.mark.smoke
def test_exact_selection_refuses_a_mismatched_action(repo_with_baseline):
    repo = repo_with_baseline
    before = _history_length(repo)

    _write(repo, "added.txt", "new file\n")
    # `added.txt` is new, so declaring it a modify does not match reality.
    selection = _write_selection(
        repo,
        "selection.json",
        json.dumps(_selection([_entry("added.txt", "modify", _md5("new file\n"))])),
    )

    result = _commit_exact(repo, "Should be refused", "--exact-selection", selection)

    assert result.returncode == 3
    assert "revision" not in result.stdout  # no result JSON; only progress text
    assert "refused" in result.stderr
    # The structured error kind is printed as JSON on stderr.
    kind = json.loads(result.stderr[result.stderr.index("{") :])
    assert kind["kind"].endswith("SelectionMismatch")
    assert kind["actionMismatches"] == [
        {"path": "added.txt", "expected": "modify", "actual": "add"}
    ]

    assert _history_length(repo) == before
    assert "added.txt" in _dirty_paths(repo)


@pytest.mark.smoke
def test_exact_selection_missing_file_fails_without_committing(repo_with_baseline):
    repo = repo_with_baseline
    before = _history_length(repo)
    _write(repo, "added.txt", "new file\n")

    missing = os.path.join(os.path.dirname(repo.path), "does-not-exist.json")
    result = _commit_exact(repo, "No file", "--exact-selection", missing)

    assert result.returncode == 3
    assert "revision" not in result.stdout  # no result JSON; only progress text
    assert "Unable to read the selection file" in result.stderr
    assert _history_length(repo) == before


@pytest.mark.smoke
@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        ("bad-json.json", "{ not json", "is not valid JSON"),
        ("not-an-object.json", "[1, 2, 3]", "must hold a JSON object"),
        ("no-files.json", "{}", "is not a valid selection"),
        (
            "bad-action.json",
            json.dumps(_selection([_entry("added.txt", "rename", _md5("new file\n"))])),
            "is not a valid selection",
        ),
    ],
)
def test_exact_selection_malformed_file_fails_without_committing(
    repo_with_baseline, name, text, expected
):
    repo = repo_with_baseline
    before = _history_length(repo)
    _write(repo, "added.txt", "new file\n")
    selection = _write_selection(repo, name, text)

    result = _commit_exact(repo, "Malformed", "--exact-selection", selection)

    assert result.returncode == 3
    assert "revision" not in result.stdout  # no result JSON; only progress text
    assert expected in result.stderr
    assert _history_length(repo) == before
    assert "added.txt" in _dirty_paths(repo)


@pytest.mark.smoke
def test_exact_selection_conflicts_with_link(repo_with_baseline):
    repo = repo_with_baseline
    before = _history_length(repo)
    selection = _write_selection(
        repo,
        "selection.json",
        json.dumps(_selection([_entry("a.txt", "add", _md5("x\n"))])),
    )

    result = _commit_exact(
        repo, "Conflict", "--exact-selection", selection, "--link", "some/link"
    )

    assert result.returncode != 0
    assert "cannot be used with" in result.stderr
    assert "--exact-selection" in result.stderr
    assert _history_length(repo) == before


@pytest.mark.smoke
@pytest.mark.parametrize(
    ("source_hash", "expected_kind"),
    [
        (_md5("different content\n"), "sourceHashMismatch"),
        (None, "malformedSourceHash"),
    ],
)
def test_exact_selection_refuses_a_bad_source_hash(
    repo_with_baseline, source_hash, expected_kind
):
    repo = repo_with_baseline
    before = _history_length(repo)
    _write(repo, "added.txt", "new file\n")
    selection = _write_selection(
        repo,
        "selection.json",
        json.dumps(_selection([_entry("added.txt", "add", source_hash)])),
    )

    result = _commit_exact(repo, "Bad hash", "--exact-selection", selection)

    assert result.returncode == 3
    assert "revision" not in result.stdout  # no result JSON; only progress text
    kind = json.loads(result.stderr[result.stderr.index("{") :])
    assert kind["kind"] == expected_kind
    assert _history_length(repo) == before
    assert "added.txt" in _dirty_paths(repo)


@pytest.mark.smoke
def test_exact_selection_json_flag_prints_one_compact_line(repo_with_baseline):
    repo = repo_with_baseline
    _write(repo, "added.txt", "new file\n")
    selection = _write_selection(
        repo,
        "selection.json",
        json.dumps(_selection([_entry("added.txt", "add", _md5("new file\n"))])),
    )

    result = _commit_exact(
        repo, "Json commit", "--exact-selection", selection, global_args=("--json",)
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["revision"]
    assert [row["path"] for row in payload["effectiveActions"]] == ["added.txt"]
    assert repo.revision_info(offline=True).message == "Json commit"


def _write_bytes(repo: Lore, path: str, content: bytes) -> None:
    full_path = os.path.join(repo.path, path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "wb") as output_file:
        output_file.write(content)


def _modify_entry_commit(
    repo: Lore, message: str, path: str, content: bytes
) -> subprocess.CompletedProcess[str]:
    selection = _write_selection(
        repo,
        f"selection-{hashlib.md5(message.encode()).hexdigest()}.json",
        json.dumps(
            _selection([_entry(path, "modify", hashlib.md5(content).hexdigest())])
        ),
    )
    return _commit_exact(
        repo, message, "--exact-selection", selection, global_args=("--json",)
    )


@pytest.mark.parametrize("push_between", [False, True], ids=["no-push", "push"])
@pytest.mark.parametrize("size", [3000, 3_000_000])
def test_exact_selection_commits_old_bytes_written_back_in_a_second_clone(
    new_lore_repo, size, push_between
):
    """A clone's local store holds only a header-only, durable entry for content it realized
    (cache off by default). Writing those exact bytes back stages no payload, so the source-hash
    check must take the bytes from the working-tree file instead of failing with
    `missing immutable content`."""
    path = "Content/actor.uasset"
    v1 = os.urandom(size)
    changed = bytearray(v1)
    changed[size // 2] ^= 0xFF
    v2 = bytes(changed)

    origin: Lore = new_lore_repo()
    _write_bytes(origin, path, v1)
    origin.stage(scan=True, offline=True)
    origin.commit("v1", offline=True)
    origin.push()

    writer = origin.clone()
    _write_bytes(writer, path, v2)
    modified = _modify_entry_commit(writer, "v2", path, v2)
    assert modified.returncode == 0, modified.stderr
    if push_between:
        writer.push()

    _write_bytes(writer, path, v1)
    reverted = _modify_entry_commit(writer, "back to v1", path, v1)

    assert reverted.returncode == 0, reverted.stderr
    payload = json.loads(reverted.stdout.strip().splitlines()[-1])
    assert [(row["path"], row["action"]) for row in payload["effectiveActions"]] == [
        (path, "modify")
    ]
    writer.push()

    fresh = origin.clone()
    with open(os.path.join(fresh.path, path), "rb") as input_file:
        assert input_file.read() == v1
