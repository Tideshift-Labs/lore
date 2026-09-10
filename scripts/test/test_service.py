# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
import logging
import json
from pathlib import Path
from uuid import UUID
import os

import pytest

from error_types import ServiceCallError
from lore import Lore
from service_util import LORE_SERVICE_ENVIRONMENT

logger = logging.getLogger(__name__)


def _assert_managed_push_settled(repo):
    journal = Path(repo.path) / ".lore-workflow"
    raw = (journal / "attempts").read_bytes()
    assert raw[0] == 2
    root = json.loads(raw[1:])
    stages = [
        parent for parent in root["parents"] if parent["operation"] == "push-stage"
    ]
    assert stages, "service push must publish its durable stages in the caller worktree"
    assert all(
        parent["complete"]
        and parent["body_completed"]
        and parent.get("parent_uncertainty_code") is None
        for parent in stages
    )
    stage_ids = {parent["id"] for parent in stages}
    paths = list(journal.glob("attempts-v2-*/*/*.json"))
    assert 0 < len(paths) < 1000, "bounded service fixture must have durable children"
    assert not list(journal.glob("attempts-v2-*/pending/*.json"))
    pushes = []
    for path in paths:
        child = json.loads(path.read_text(encoding="utf-8"))
        assert child["version"] == 2
        if child.get("managed", {}).get("parent_id") not in stage_ids:
            continue
        assert UUID(child["attempt"]["repository"]).hex == UUID(repo.get_id()).hex
        assert child["attempt"]["state"]["state"] == "resolved"
        if child["managed"]["rpc"] == "RevisionService.BranchPush":
            pushes.append(child)
            assert child["attempt"]["state"]["resolution"] == "applied"
    assert pushes, "completed stages must contain an Applied BranchPush receipt"


@pytest.mark.smoke
@pytest.mark.skip(reason="Unknown issue specifically running in CI for OSS")
def test_service_down(new_lore_repo):
    with pytest.raises(ServiceCallError):
        new_lore_repo(environment_vars=LORE_SERVICE_ENVIRONMENT.copy())


@pytest.mark.smoke
def test_service_call(new_lore_repo, background_lore_service):
    repo: Lore = new_lore_repo(environment_vars=LORE_SERVICE_ENVIRONMENT.copy())

    # Add a single file so status has output
    file_name = "test.uasset"
    with repo.open_file(file_name, "w+b") as output_file:
        output_file.write(os.urandom(30))

    repo.stage(scan=True)

    status_output = repo.status()

    # Assert that single file is added
    assert "A " + file_name in map(
        lambda line: line.strip(" "), status_output.splitlines()
    )


@pytest.mark.smoke
def test_service_resolves_relative_paths_against_caller(
    new_lore_repo, lore_service_runner, tmp_path
):
    """Relative paths belong to the directory the command was run in.

    The service resolves them, and its own working directory is unrelated to
    the caller's, so a service started elsewhere must not pull them towards
    itself. Every other service test passes an absolute repository path, which
    cannot catch this.
    """
    # Start the service in a directory unrelated to where the commands run, so
    # that a relative path resolved there rather than at the caller would show.
    service_directory = tmp_path / "service_elsewhere"
    caller_directory = tmp_path / "caller"
    service_directory.mkdir()
    caller_directory.mkdir()
    lore_service_runner.start(str(service_directory))

    # Seed a remote to clone from. Routed through the service like the rest,
    # but against the repository's own absolute path, so unaffected by the
    # service's directory.
    source: Lore = new_lore_repo(environment_vars=LORE_SERVICE_ENVIRONMENT.copy())
    with source.open_file("seed.txt", "w+") as seed_file:
        seed_file.write("seed\n")
    source.stage(scan=True, offline=True)
    source.commit("Seed", offline=True)
    source.push()
    _assert_managed_push_settled(source)

    # Clone to a relative path from the caller's directory. It must land there,
    # not under the service's directory.
    clone_name = "relative_clone"
    source.run(
        ["repository", "clone", source.remote_path, clone_name],
        cwd=str(caller_directory),
        use_os_dir=True,
    )

    clone_path = caller_directory / clone_name
    assert (clone_path / ".lore").is_dir(), (
        f"Clone must land under the caller's directory, not the service's. "
        f"{caller_directory} contains {list(caller_directory.iterdir())}"
    )
    assert not (service_directory / clone_name).exists(), (
        f"Clone must not land under the service's directory. "
        f"{service_directory} contains {list(service_directory.iterdir())}"
    )

    # Stage a relative path from inside the clone.
    clone = Lore(
        lore_executable_path=source.lore_executable_path,
        path=str(clone_path),
        name=clone_name,
        global_dir=source.global_dir,
        environment_vars=source.environment_vars.copy(),
        remote_url=source.remote,
        remote_path=source.remote_path,
        create_repo=False,
    )
    file_name = "added.uasset"
    added_contents = os.urandom(30)
    (clone_path / file_name).write_bytes(added_contents)
    clone.stage(file_name, relative_paths=True)

    status_output = clone.status()
    assert "A " + file_name in map(
        lambda line: line.strip(" "), status_output.splitlines()
    ), f"Staged file should show as added: {status_output}"

    clone.commit("Relative service push", offline=True)
    clone.run(
        ["--repository", clone_name, "push"],
        cwd=str(caller_directory),
        use_os_dir=True,
    )
    _assert_managed_push_settled(clone)
    assert not (service_directory / ".lore-workflow").exists()
    verification = clone.clone()
    with verification.open_file(file_name, "rb") as contents:
        assert contents.read() == added_contents
