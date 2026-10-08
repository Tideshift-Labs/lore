# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
"""Layout gate: a crate with `[lib] test = false` must not carry `#[cfg(test)]` in `src/`.

Cargo skips the lib unit-test harness when `test = false`, so any `#[cfg(test)]` module in
that crate's `src/` silently stops running. This gate needs no built server.

Two things are not offenders. A `//` comment line (including `//!` and `///` doc comments) that
only mentions the attribute. And a file that belongs to a bin target whose own test harness is
enabled: its root file, or any file under its `src/bin/<name>/` directory. Every other file under
`src/` stays strict, because a module shared with the lib still only runs through the lib harness.
"""

import re
import tomllib
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
CFG_TEST = re.compile(r"#\s*\[\s*cfg\s*\((?:[^)]*[(,\s])?test\b")
COMMENT_LINE = re.compile(r"^\s*//")


def workspace_crate_dirs(root: Path) -> list[Path]:
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    members = manifest.get("workspace", {}).get("members", [])
    dirs: list[Path] = []
    for member in members:
        if any(ch in member for ch in "*?["):
            dirs.extend(
                sorted(p for p in root.glob(member) if (p / "Cargo.toml").is_file())
            )
        elif (root / member / "Cargo.toml").is_file():
            dirs.append(root / member)
    return dirs


def _manifest(crate_dir: Path) -> dict:
    return tomllib.loads((crate_dir / "Cargo.toml").read_text(encoding="utf-8"))


def lib_tests_disabled(crate_dir: Path) -> bool:
    return _manifest(crate_dir).get("lib", {}).get("test") is False


def bin_paths_with_tests(crate_dir: Path) -> tuple[set[Path], set[Path]]:
    """Files and directories owned by a bin target whose test harness runs.

    Returns `(root_files, bin_dirs)`. Explicit `[[bin]]` entries count unless they set
    `test = false`. Auto-discovered bins (`src/main.rs`, `src/bin/*.rs`, `src/bin/*/main.rs`)
    count unless `autobins = false` or an explicit entry with the same name disables tests.
    """
    manifest = _manifest(crate_dir)
    package = manifest.get("package", {})
    explicit = manifest.get("bin", [])
    disabled_names = {b.get("name") for b in explicit if b.get("test") is False}
    roots: set[Path] = set()
    dirs: set[Path] = set()

    def add_root(path: Path) -> None:
        path = path.resolve()
        roots.add(path)
        bin_dir = (crate_dir / "src" / "bin").resolve()
        if path.name == "main.rs" and path.parent.parent == bin_dir:
            dirs.add(path.parent)

    for entry in explicit:
        if entry.get("test") is False:
            continue
        if "path" in entry:
            add_root(crate_dir / entry["path"])
        elif "name" in entry:
            for candidate in (
                crate_dir / "src" / "bin" / f"{entry['name']}.rs",
                crate_dir / "src" / "bin" / entry["name"] / "main.rs",
            ):
                if candidate.is_file():
                    add_root(candidate)

    if package.get("autobins", True) is not False:
        main = crate_dir / "src" / "main.rs"
        if main.is_file() and package.get("name") not in disabled_names:
            add_root(main)
        bin_dir = crate_dir / "src" / "bin"
        if bin_dir.is_dir():
            for path in bin_dir.glob("*.rs"):
                if path.stem not in disabled_names:
                    add_root(path)
            for path in bin_dir.glob("*/main.rs"):
                if path.parent.name not in disabled_names:
                    add_root(path)
    return roots, dirs


def _belongs_to_tested_bin(path: Path, roots: set[Path], dirs: set[Path]) -> bool:
    resolved = path.resolve()
    return resolved in roots or any(d in resolved.parents for d in dirs)


def find_offenders(root: Path) -> list[str]:
    """Return `crate: path:line` for every cfg(test) under src/ of a `test = false` lib."""
    offenders: list[str] = []
    for crate_dir in workspace_crate_dirs(root):
        if not lib_tests_disabled(crate_dir):
            continue
        roots, dirs = bin_paths_with_tests(crate_dir)
        src = crate_dir / "src"
        for path in sorted(src.rglob("*.rs")):
            if _belongs_to_tested_bin(path, roots, dirs):
                continue
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                if COMMENT_LINE.match(line):
                    continue
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
        '[package]\nname = "fake"\nversion = "0.0.0"\n\n[lib]\ntest = false\n',
        encoding="utf-8",
    )
    (fake / "src" / "lib.rs").write_text(
        "pub fn f() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n",
        encoding="utf-8",
    )
    ok = tmp_path / "ok"
    (ok / "src").mkdir(parents=True)
    (ok / "Cargo.toml").write_text(
        '[package]\nname = "ok"\nversion = "0.0.0"\n', encoding="utf-8"
    )
    (ok / "src" / "lib.rs").write_text("#[cfg(test)]\nmod tests {}\n", encoding="utf-8")

    assert find_offenders(tmp_path) == ["fake: src/lib.rs:3"]


def _write_crate(
    root: Path, name: str, manifest_extra: str, files: dict[str, str]
) -> None:
    crate = root / name
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.0.0"\n\n[lib]\ntest = false\n'
        + manifest_extra,
        encoding="utf-8",
    )
    for rel, text in files.items():
        path = crate / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def test_checker_ignores_comment_lines(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["c"]\n', encoding="utf-8"
    )
    _write_crate(
        tmp_path,
        "c",
        "",
        {
            "src/lib.rs": (
                "//! It is deliberately not `#[cfg(test)]`.\n"
                "/// Not `#[cfg(test)]` either.\n"
                "    // #[cfg(test)] commented out\n"
                "pub fn f() {}\n"
                "#[cfg(test)]\n"
                "mod tests {}\n"
            )
        },
    )

    assert find_offenders(tmp_path) == ["c: src/lib.rs:5"]


def test_checker_skips_a_tested_bin_but_not_lib_modules(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["c", "d"]\n', encoding="utf-8"
    )
    cfg_test = "#[cfg(test)]\nmod tests {}\n"
    # Explicit [[bin]] with its tests enabled, plus an auto-discovered bin directory.
    _write_crate(
        tmp_path,
        "c",
        '\n[[bin]]\nname = "stamp"\npath = "src/bin/stamp.rs"\n',
        {
            "src/lib.rs": "pub mod shared;\n",
            "src/shared.rs": cfg_test,
            "src/bin/stamp.rs": "fn main() {}\n" + cfg_test,
            "src/bin/tool/main.rs": "mod helper;\nfn main() {}\n" + cfg_test,
            "src/bin/tool/helper.rs": cfg_test,
        },
    )
    # A bin whose own tests are disabled stays strict.
    _write_crate(
        tmp_path,
        "d",
        '\n[[bin]]\nname = "quiet"\npath = "src/bin/quiet.rs"\ntest = false\n',
        {"src/lib.rs": "", "src/bin/quiet.rs": "fn main() {}\n" + cfg_test},
    )

    assert find_offenders(tmp_path) == ["c: src/shared.rs:1", "d: src/bin/quiet.rs:2"]
