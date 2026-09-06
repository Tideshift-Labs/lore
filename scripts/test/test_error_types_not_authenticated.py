# Copyright 2026 Khurram Virani
# SPDX-License-Identifier: MIT
r"""Pure-Python unit tests for `error_types.get_error_type`'s hoisted
`Not authenticated` classification.

No server, no built `lore` binary: these construct a `CalledProcessError`
by hand and call `get_error_type` directly, so they belong in the fast tier
and run under plain `uv run pytest` without any of the CLI/server fixtures
the rest of this directory needs.

The hoisted, anchored pattern in `error_types.py`'s `ERROR_MAP` exists
because two things would otherwise misclassify real CLI output:

1. `lore-client/src/cli/logging.rs` colors output UNCONDITIONALLY, so a
   captured line starts with SGR escapes (`\x1b[1m\x1b[31m[Error] ...`), not
   with `[`. A pattern anchored on `^\[Error\]` would never match real
   output at all.
2. `NotAuthenticated` now renders as `Not authenticated: <reason>`, and the
   reason is server-supplied text that can quote another entry's substring
   verbatim (e.g. "Not authorized to access repository"). An unanchored,
   un-hoisted match on that phrase would let the reason steal the
   classification from the real error. The anchor must also require the
   exact `[Error]` tag, not any bracketed word, or an incidental
   `[Warn] Not authenticated: retrying` line earlier in the captured output
   could steal the classification from a real `[Error]` failure below it.
"""

from subprocess import CalledProcessError

from error_types import (
    BranchDivergedError,
    NotAuthenticatedError,
    ProtectedError,
    get_error_type,
)


def _error_with_output(output: str) -> CalledProcessError:
    """Build a `CalledProcessError` whose combined stdout+stderr is `output`.

    `get_error_type` reads `(e.stdout or "") + (e.stderr or "")`, and
    `CalledProcessError`'s `stdout` property is an alias for the
    constructor's `output` argument -- stderr is left `None` here since
    every case below puts its text on the stdout side, matching how the
    CLI's own captured output is assembled.
    """
    return CalledProcessError(returncode=1, cmd=["lore"], output=output)


def test_colored_real_cli_output_classifies_as_not_authenticated():
    """The actual shape of real CLI output: SGR color escapes, then the
    `[Error]` tag, then the server's reason. This is the case the anchor
    exists to match -- without the escape group it would never fire."""
    output = (
        "\x1b[1m\x1b[31m[Error] Not authenticated: bearer audience "
        "commit0-storage is not the human authn audience\x1b[0m\n"
    )
    assert get_error_type(_error_with_output(output)) is NotAuthenticatedError


def test_a_reason_quoting_not_authorized_does_not_steal_to_protected_error():
    """The reason is server-chosen text and can quote another entry's
    substring verbatim. The hoisted, anchored entry must win over the
    generic 'Not authorized to access repository' entry lower in the map."""
    output = (
        "\x1b[1m\x1b[31m[Error] Not authenticated: Not authorized to "
        "access repository\x1b[0m\n"
    )
    assert get_error_type(_error_with_output(output)) is NotAuthenticatedError


def test_an_incidental_warn_line_does_not_steal_from_a_real_error_below_it():
    """`(?m)^` matches every line of the captured output, so a permissive
    level tag would let an earlier `[Warn]` line steal the classification
    from the real `[Error]` failure that follows it."""
    output = (
        "\x1b[33m[Warn] Not authenticated: retrying\x1b[0m\n"
        "\x1b[1m\x1b[31m[Error] Branch has diverged\x1b[0m\n"
    )
    assert get_error_type(_error_with_output(output)) is BranchDivergedError


def test_a_genuine_not_authorized_still_classifies_as_protected_error():
    """Regression pin: fixing the `NotAuthenticated` hoist must not disturb
    the unrelated, genuine `NotAuthorized` classification."""
    output = "\x1b[1m\x1b[31m[Error] Not authorized to access repository\x1b[0m\n"
    assert get_error_type(_error_with_output(output)) is ProtectedError


def test_uncolored_not_authenticated_output_still_classifies():
    """The anchor group is `(?:\\x1b\\[[0-9;]*m)*`, zero-or-more, so plain
    (non-colored) output -- e.g. NO_COLOR, or captured through a pipe that
    strips escapes upstream -- must still match."""
    output = "[Error] Not authenticated: the server stated no reason\n"
    assert get_error_type(_error_with_output(output)) is NotAuthenticatedError
