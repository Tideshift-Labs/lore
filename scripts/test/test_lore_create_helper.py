# Copyright 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Deferred repository IDs remain bound across failed CLI creation attempts."""

import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lore import Lore
from error_types import UnknownLoreError


class DeferredCreateTests(unittest.TestCase):
    def test_preallocated_id_survives_unchecked_failure_and_is_consumed_once(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Lore(
                "fixture-cli",
                directory,
                "fixture",
                directory,
                repo_id="11111111111111111111111111111111",
                create_repo=False,
            )
            replies = [
                subprocess.CompletedProcess([], code, "", "") for code in (1, 0, 0)
            ]
            with (
                patch("lore.subprocess.run", side_effect=replies) as run,
                patch.object(repo, "_ensure_test_identity_in_config") as seed,
            ):
                repo.repository_create(check=False)
                seed.assert_not_called()
                self.assertEqual(
                    repo._pending_create_repo_id, "11111111111111111111111111111111"
                )
                repo.repository_create()
                self.assertIsNone(repo._pending_create_repo_id)
                repo.repository_create()
                first, second, third = [call.args[0] for call in run.call_args_list]
                for command in (first, second):
                    self.assertEqual(
                        command[command.index("--id") + 1],
                        "11111111111111111111111111111111",
                    )
                self.assertNotIn("--id", third)
                self.assertEqual(seed.call_count, 2)

    def test_raised_failure_retains_preallocated_id(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Lore(
                "fixture-cli",
                directory,
                "fixture",
                directory,
                repo_id="22222222222222222222222222222222",
                create_repo=False,
            )
            failure = subprocess.CalledProcessError(1, ["fixture-cli"], "denied", "")
            with (
                patch("lore.subprocess.run", side_effect=failure),
                patch.object(repo, "_ensure_test_identity_in_config") as seed,
            ):
                with self.assertRaises(UnknownLoreError):
                    repo.repository_create()
                self.assertEqual(
                    repo._pending_create_repo_id, "22222222222222222222222222222222"
                )
                seed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
