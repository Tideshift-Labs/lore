# SPDX-FileCopyrightText: 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Opt-in retention of loreserver logs, so a failed test shows the server side.

By default a server writes `server.log` inside its own root, and that root is
deleted with the test or class that made it. A failure such as a Put whose
answer was lost then has only the client's half of the story.

Set `LORE_TEST_SERVER_LOG_DIR` to an existing directory and every server the
suite launches writes its log there instead, named after the test that was
running when it started:

    server-<pid>-<seq>-<test>.log

When a test fails, each server log that was open during it is sliced to the
bytes written between the test's start and the failing report, and the slices
go to one file per failed phase:

    FAILED-<pid>-<seq>-<test>-<phase>.log

The failure report gains a "Lore server logs" section naming that file and the
full logs it came from. At the end of the session, full logs that saw no
failure are deleted and the rest are gzipped; set `LORE_TEST_SERVER_LOG_KEEP=all`
to keep every one as written. A log whose server is still running at that
point (gw0's shared server under xdist, or a leaked one), or that cannot be
removed, is left as written and listed in the terminal summary.

The bookkeeping is per process. Under xdist a worker sees only the servers it
launched itself, so the shared session server on gw0 is not sliced for tests
on other workers.
"""

import gzip
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import pytest

_DIR_ENV = "LORE_TEST_SERVER_LOG_DIR"
_KEEP_ENV = "LORE_TEST_SERVER_LOG_KEEP"
_SLUG_MAX = 80
# Windows MAX_PATH, less room for the ".gz" a kept log gains at session end.
_PATH_MAX = 256


@dataclass
class _ServerLog:
    path: Path
    process: object = None
    # Byte offset at the start of the current test, or None when the server
    # was not running then. A log created during the test starts at zero.
    window_start: int | None = 0
    failed: bool = False
    retired: bool = False


@dataclass
class _State:
    directory: Path | None = None
    keep_all: bool = False
    current_nodeid: str | None = None
    sequence: int = 0
    logs: list[_ServerLog] = field(default_factory=list)
    excerpts: list[Path] = field(default_factory=list)
    left_behind: list[Path] = field(default_factory=list)


_state = _State()


def _next_path(prefix: str, label: str) -> Path:
    """A unique log path, its test label trimmed to stay under Windows MAX_PATH."""
    _state.sequence += 1
    head = f"{prefix}-{os.getpid()}-{_state.sequence:04d}-"
    room = _PATH_MAX - len(str(_state.directory)) - len(head) - len(".log") - 1
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_")
    slug = slug[-max(min(room, _SLUG_MAX), 8) :] or "session"
    return _state.directory / f"{head}{slug}.log"


def server_log_path(server_root: Path) -> Path:
    """Where a server launched now writes its log."""
    if _state.directory is None:
        return server_root / "server.log"
    return _next_path("server", _state.current_nodeid or "session")


def track(path: Path, process) -> None:
    """Follow a launched server's log so a failing test can slice it."""
    if _state.directory is None:
        return
    _state.logs.append(_ServerLog(path=path, process=process))


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _alive(log: _ServerLog) -> bool:
    return log.process is not None and log.process.poll() is None


def _read_slice(path: Path, start: int) -> bytes:
    try:
        with path.open("rb") as handle:
            handle.seek(start)
            return handle.read()
    except OSError as error:
        return f"<could not read {path}: {error}>\n".encode()


def _write_excerpt(report, windows: list[tuple[_ServerLog, int, int]]) -> Path:
    excerpt = _next_path("FAILED", f"{report.nodeid}-{report.when}")
    with excerpt.open("wb") as out:
        out.write(f"Failed test: {report.nodeid} ({report.when})\n".encode())
        for log, start, end in windows:
            out.write(f"\n===== {log.path} bytes {start}..{end} =====\n".encode())
            out.write(_read_slice(log.path, start)[: end - start])
    _state.excerpts.append(excerpt)
    return excerpt


def pytest_configure(config):
    directory = os.environ.get(_DIR_ENV)
    if not directory:
        return
    root = Path(directory)
    if not root.is_absolute() or not root.is_dir():
        raise pytest.UsageError(f"{_DIR_ENV} must name an existing absolute directory")
    _state.directory = root
    _state.keep_all = os.environ.get(_KEEP_ENV, "").lower() == "all"


def pytest_runtest_logstart(nodeid, location):
    if _state.directory is None:
        return
    _state.current_nodeid = nodeid
    for log in _state.logs:
        if not log.retired:
            log.window_start = _size(log.path) if _alive(log) else None


def pytest_runtest_logfinish(nodeid, location):
    if _state.directory is None:
        return
    _state.current_nodeid = None
    for log in _state.logs:
        if not log.retired and not _alive(log):
            log.retired = True


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if _state.directory is None or not report.failed:
        return
    windows = []
    for log in _state.logs:
        if log.retired or log.window_start is None:
            continue
        end = _size(log.path)
        if end > log.window_start:
            windows.append((log, log.window_start, end))
            log.failed = True
    if not windows:
        report.sections.append(
            (
                "Lore server logs",
                "No server launched by this process wrote to its log during this test.",
            )
        )
        return
    excerpt = _write_excerpt(report, windows)
    lines = [f"Server output during this test: {excerpt}"]
    suffix = "" if _state.keep_all else " (gzipped to .log.gz at session end)"
    lines += [f"Full log: {log.path}{suffix}" for log, _, _ in windows]
    report.sections.append(("Lore server logs", "\n".join(lines)))


def _compress(path: Path) -> Path:
    """Gzip a kept full log: a session server's log spans the whole run."""
    target = path.with_name(path.name + ".gz")
    try:
        with path.open("rb") as source, gzip.open(target, "wb") as out:
            shutil.copyfileobj(source, out)
        path.unlink()
    except OSError:
        target.unlink(missing_ok=True)
        return path
    return target


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if _state.directory is None or _state.keep_all:
        return
    for log in _state.logs:
        if _alive(log):
            _state.left_behind.append(log.path)
            continue
        if log.failed:
            log.path = _compress(log.path)
            continue
        try:
            log.path.unlink(missing_ok=True)
        except OSError:
            _state.left_behind.append(log.path)


def pytest_terminal_summary(terminalreporter):
    if _state.directory is None:
        return
    kept = [log.path for log in _state.logs if log.failed or _state.keep_all]
    if not (_state.excerpts or kept or _state.left_behind):
        return
    terminalreporter.section("Lore server logs")
    for excerpt in _state.excerpts:
        terminalreporter.line(f"failed-test excerpt: {excerpt}")
    for path in kept:
        terminalreporter.line(f"kept full log: {path}")
    for path in _state.left_behind:
        if path not in kept:
            terminalreporter.line(
                f"not removed (server still running or file locked): {path}"
            )
