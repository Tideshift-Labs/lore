# SPDX-FileCopyrightText: 2026 Khurram Virani
# SPDX-License-Identifier: MIT
import gzip
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

# A real pytest session drives the plugin. Each "server" is an idle child
# process tracked like loreserver; the tests append to its log to stand in for
# server output, so the bytes in each test's window are known exactly.
_INNER_TESTS = """
import subprocess, sys
import pytest
import scripts.test.server_logs as server_logs

def _launch(root):
    path = server_logs.server_log_path(root)
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    server_logs.track(path, process)
    path.write_text("startup\\n")
    return path, process

def _write(path, text):
    with path.open("a") as log:
        log.write(text + "\\n")

@pytest.fixture(scope="session")
def shared(tmp_path_factory):
    path, process = _launch(tmp_path_factory.mktemp("shared"))
    yield path
    process.kill()
    process.wait()

@pytest.fixture
def own(tmp_path):
    path, process = _launch(tmp_path)
    yield path
    process.kill()
    process.wait()

def test_a_passes(shared, own):
    _write(shared, "during-pass")
    _write(own, "own-pass")

def test_b_fails(shared):
    _write(shared, "during-fail")
    assert False, "forced"
"""


def _run(directory: Path, keep: str | None):
    source = directory / "test_inner.py"
    source.write_text(_INNER_TESTS, encoding="utf-8")
    config = directory / "pytest.ini"
    config.write_text("[pytest]\n", encoding="utf-8")
    logs = directory / "logs"
    logs.mkdir()
    env = {
        **os.environ,
        "LORE_TEST_SERVER_LOG_DIR": str(logs),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    env.pop("LORE_TEST_SERVER_LOG_KEEP", None)
    if keep is not None:
        env["LORE_TEST_SERVER_LOG_KEEP"] = keep
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTEST_PLUGINS", None)
    child = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "scripts.test.server_logs",
            "-c",
            str(config),
            "--confcutdir",
            str(directory),
            "--basetemp",
            str(directory / "basetemp"),
            str(source),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return child, logs


class ServerLogsTests(unittest.TestCase):
    def test_failure_names_an_excerpt_of_only_its_own_window(self):
        with TemporaryDirectory() as directory:
            child, logs = _run(Path(directory), keep=None)
            self.assertEqual(child.returncode, 1, child.stdout + child.stderr)
            excerpts = list(logs.glob("FAILED-*test_b_fails-call.log"))
            self.assertEqual(len(excerpts), 1, sorted(p.name for p in logs.iterdir()))
            self.assertIn(
                f"Server output during this test: {excerpts[0]}", child.stdout
            )
            text = excerpts[0].read_text()
            self.assertIn("during-fail", text)
            self.assertNotIn("during-pass", text)
            self.assertNotIn("startup", text)

            # The shared log saw the failure: kept whole, gzipped. The passing
            # test's own server log is deleted.
            kept = list(logs.glob("server-*.log.gz"))
            self.assertEqual(len(kept), 1, sorted(p.name for p in logs.iterdir()))
            whole = gzip.decompress(kept[0].read_bytes()).decode()
            for line in ("startup", "during-pass", "during-fail"):
                self.assertIn(line, whole)
            self.assertEqual(list(logs.glob("server-*.log")), [])
            self.assertIn(f"kept full log: {kept[0]}", child.stdout)

    def test_keep_all_leaves_every_log_as_written(self):
        with TemporaryDirectory() as directory:
            child, logs = _run(Path(directory), keep="all")
            self.assertEqual(child.returncode, 1, child.stdout + child.stderr)
            self.assertEqual(len(list(logs.glob("server-*.log"))), 2)
            self.assertEqual(list(logs.glob("*.gz")), [])
            own = [p for p in logs.glob("server-*.log") if "own-pass" in p.read_text()]
            self.assertEqual(len(own), 1)


if __name__ == "__main__":
    unittest.main()
