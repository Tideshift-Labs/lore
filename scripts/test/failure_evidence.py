# SPDX-FileCopyrightText: 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Opt-in failure-only JSONL, fsynced before pytest continues to the next report."""

import json
import os
from pathlib import Path
import re
import threading


def _redact(value):
    # Platform PATs are lhp_ + base64url(32 random bytes), independent of CLI syntax.
    value = re.sub(r"lhp_[A-Za-z0-9_-]+", "[REDACTED PAT]", value)
    value = re.sub(
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED JWT]", value
    )
    return re.sub(
        r"(?i)(Bearer\s+|--token(?:=|\s+))[^\s'\"\],)]+", r"\1[REDACTED]", value
    )


class FailureEvidence:
    def __init__(self, directory):
        root = Path(directory)
        if not root.is_absolute() or not root.is_dir():
            raise ValueError(
                "Failure evidence requires an existing absolute owned directory"
            )
        if os.path.normcase(str(root.resolve())) != os.path.normcase(
            os.path.abspath(root)
        ):
            raise ValueError("Failure evidence directory must not redirect")
        self.path = root / f"failures-{os.getpid()}.jsonl"
        self._file = self.path.open("x", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()

    def record(self, report):
        if not report.failed:
            return
        # Never serialize report.__dict__, sections, capstdout, capstderr, or environment.
        row = {
            "nodeid": _redact(report.nodeid),
            "phase": report.when,
            "longrepr": _redact(report.longreprtext),
        }
        with self._lock:
            self._file.write(json.dumps(row, ensure_ascii=False) + "\n")
            self._file.flush()
            os.fsync(self._file.fileno())

    def close(self):
        self._file.close()


_sink = None


def pytest_configure(config):
    global _sink
    directory = os.environ.get("LH_PYTEST_FAILURE_EVIDENCE_DIR")
    if directory:
        _sink = FailureEvidence(directory)


def pytest_runtest_logreport(report):
    if _sink is not None:
        _sink.record(report)


def pytest_unconfigure(config):
    global _sink
    if _sink is not None:
        _sink.close()
        _sink = None
