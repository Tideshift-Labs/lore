# SPDX-FileCopyrightText: 2026 Khurram Virani
# SPDX-License-Identifier: MIT
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.test.failure_evidence import FailureEvidence


class FailureEvidenceTests(unittest.TestCase):
    def test_actual_pytest_failure_survives_later_process_abort(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "pytest.ini"
            config.write_text("[pytest]\n", encoding="utf-8")
            source = root / "test_abort.py"
            source.write_text(
                "import os\n"
                "def test_a_failure():\n    print('captured-secret-output')\n    assert False, 'durable-reason'\n"
                "def test_z_abort():\n    os._exit(17)\n",
                encoding="utf-8",
            )
            env = {
                **os.environ,
                "LH_PYTEST_FAILURE_EVIDENCE_DIR": directory,
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            }
            env.pop("PYTEST_ADDOPTS", None)
            env.pop("PYTEST_PLUGINS", None)
            child = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-p",
                    "scripts.test.failure_evidence",
                    "-c",
                    str(config),
                    "--confcutdir",
                    directory,
                    str(source),
                ],
                cwd=Path(__file__).resolve().parents[2],
                env=env,
                capture_output=True,
                timeout=20,
            )
            self.assertEqual(
                child.returncode, 17, child.stderr.decode(errors="replace")
            )
            files = list(root.glob("failures-*.jsonl"))
            self.assertEqual(len(files), 1)
            rows = [json.loads(line) for line in files[0].read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["nodeid"].endswith("::test_a_failure"))
            self.assertEqual(rows[0]["phase"], "call")
            self.assertIn("durable-reason", rows[0]["longrepr"])
            self.assertNotIn("Captured stdout", rows[0]["longrepr"])

    def test_appends_and_syncs_each_failure_without_captured_output(self):
        with TemporaryDirectory() as directory:
            sink = FailureEvidence(directory)
            try:
                with patch("scripts.test.failure_evidence.os.fsync") as sync:
                    for phase in ("setup", "call", "teardown"):
                        sink.record(
                            SimpleNamespace(
                                failed=True,
                                nodeid=f"test_case.py::test_{phase}",
                                when=phase,
                                longreprtext=f"traceback {phase}",
                                capstdout="secret output",
                                sections=[("Captured log", "secret log")],
                            )
                        )
                        # A separate reader sees the record before close/final reporting.
                        rows = [
                            json.loads(line)
                            for line in sink.path.read_text().splitlines()
                        ]
                        self.assertEqual(len(rows), sync.call_count)
                    self.assertEqual(sync.call_count, 3)
                self.assertEqual(
                    [row["phase"] for row in rows], ["setup", "call", "teardown"]
                )
                self.assertEqual(set(rows[0]), {"nodeid", "phase", "longrepr"})
                self.assertNotIn("secret", sink.path.read_text())
            finally:
                sink.close()

    def test_pass_and_skip_need_no_traceback_and_write_nothing(self):
        with TemporaryDirectory() as directory:
            sink = FailureEvidence(directory)
            try:
                for outcome in ("passed", "skipped"):
                    sink.record(SimpleNamespace(failed=False, outcome=outcome))
                self.assertEqual(sink.path.read_text(), "")
            finally:
                sink.close()

    def test_redacts_credentials_embedded_in_failure_reason(self):
        with TemporaryDirectory() as directory:
            sink = FailureEvidence(directory)
            try:
                sink.record(
                    SimpleNamespace(
                        failed=True,
                        nodeid="test.py::case",
                        when="call",
                        longreprtext="eyJabc.abc.def Bearer opaque-secret --token=other-secret",
                    )
                )
                text = sink.path.read_text()
                for secret in ("eyJabc.abc.def", "opaque-secret", "other-secret"):
                    self.assertNotIn(secret, text)
            finally:
                sink.close()

    def test_redacts_standalone_quoted_pat_without_removing_diagnostic_text(self):
        with TemporaryDirectory() as directory:
            sink = FailureEvidence(directory)
            token = "lhp_" + "Ab9_-" * 8 + "XYZ"
            try:
                sink.record(
                    SimpleNamespace(
                        failed=True,
                        nodeid="test.py::case",
                        when="call",
                        longreprtext=f"CLI rejected positional '{token}'; operation refused",
                    )
                )
                row = json.loads(sink.path.read_text())
                self.assertEqual(
                    row["longrepr"],
                    "CLI rejected positional '[REDACTED PAT]'; operation refused",
                )
                self.assertNotIn(token, sink.path.read_text())
            finally:
                sink.close()

    def test_refuses_missing_relative_or_existing_evidence(self):
        with self.assertRaises(ValueError):
            FailureEvidence("relative")
        with TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                FailureEvidence(str(Path(directory) / "missing"))
            sink = FailureEvidence(directory)
            try:
                with self.assertRaises(FileExistsError):
                    FailureEvidence(directory)
            finally:
                sink.close()


if __name__ == "__main__":
    unittest.main()
