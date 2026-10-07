# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
"""Layout gate: a crate with `[lib] test = false` must not carry `#[cfg(test)]` in `src/`.

Cargo skips the lib unit-test harness when `test = false`, so any `#[cfg(test)]` module in
that crate's `src/` silently stops running. This gate needs no built server.
"""

import re
import tomllib
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
CFG_TEST = re.compile(r"#\s*\[\s*cfg\s*\((?:[^)]*[(,\s])?test\b")


def workspace_crate_dirs(root: Path) -> list[Path]:
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    members = manifest.get("workspace", {}).get("members", [])
    dirs: list[Path] = []
    for member in members:
        if any(ch in member for ch in "*?["):
            dirs.extend(sorted(p for p in root.glob(member) if (p / "Cargo.toml").is_file()))
        elif (root / member / "Cargo.toml").is_file():
            dirs.append(root / member)
    return dirs


def lib_tests_disabled(crate_dir: Path) -> bool:
    manifest = tomllib.loads((crate_dir / "Cargo.toml").read_text(encoding="utf-8"))
    return manifest.get("lib", {}).get("test") is False


def find_offenders(root: Path) -> list[str]:
    """Return `crate: path:line` for every cfg(test) under src/ of a `test = false` lib."""
    offenders: list[str] = []
    for crate_dir in workspace_crate_dirs(root):
        if not lib_tests_disabled(crate_dir):
            continue
        src = crate_dir / "src"
        for path in sorted(src.rglob("*.rs")):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if CFG_TEST.search(line):
                    rel = path.relative_to(crate_dir).as_posix()
                    offenders.append(f"{crate_dir.name}: {rel}:{lineno}")
    return offenders


def test_no_cfg_test_in_test_disabled_crates():
    offenders = find_offenders(WORKSPACE_ROOT)
    assert not offenders, (
        "cfg(test) in a crate with `[lib] test = false` (these tests never run):\n  "
        + "\n  ".join(offenders)
    )


def test_checker_flags_fake_crate(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["fake", "ok"]\n', encoding="utf-8"
    )
    fake = tmp_path / "fake"
    (fake / "src").mkdir(parents=True)
    (fake / "Cargo.toml").write_text(
        '[package]\nname = "fake"\nversion = "0.0.0"\n\n[lib]\ntest = false\n', encoding="utf-8"
    )
    (fake / "src" / "lib.rs").write_text(
        "pub fn f() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n",
        encoding="utf-8",
    )
    ok = tmp_path / "ok"
    (ok / "src").mkdir(parents=True)
    (ok / "Cargo.toml").write_text('[package]\nname = "ok"\nversion = "0.0.0"\n', encoding="utf-8")
    (ok / "src" / "lib.rs").write_text("#[cfg(test)]\nmod tests {}\n", encoding="utf-8")

    assert find_offenders(tmp_path) == ["fake: src/lib.rs:3"]
