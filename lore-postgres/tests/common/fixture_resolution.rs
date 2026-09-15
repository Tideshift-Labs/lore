// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Shared resolver for fixtures under
//! `lorehub/docs/contracts/fixtures/lore-notification-plane/`, consumed by this crate's
//! `tests/*.rs` conformance suites (WP-111 residual: standalone-checkout support).
//!
//! `lore-postgres` and `lorehub` are sibling checkouts under one `lorehub-all` container in our
//! own workspace, where the fixtures are always present. A **standalone** checkout of just this
//! repo (an upstream contributor's clone, or a fork clone without `lorehub` beside it) has no
//! such sibling at all -- that is a different fact from a fixture being merely missing or
//! unreadable *within* an existing sibling, and the two deserve different outcomes:
//!
//! - No sibling `lorehub` repo root at all -> this checkout cannot possibly have the fixtures.
//!   The calling test must print one loud, greppable notice and skip (return early) rather than
//!   fail -- see [`print_standalone_skip_notice`].
//! - A sibling `lorehub` repo root exists but the named fixture file is missing or unreadable
//!   under it -> this is fixture drift in OUR OWN workspace, exactly what every consuming test
//!   file's "must FAIL, never skip" convention exists to catch. The caller must panic (fail the
//!   test), never skip. Because `lorehub` is always present in this workspace, this is the only
//!   branch ever reachable here -- the standalone branch costs this workspace zero coverage.
//! - [`FIXTURE_DIR_OVERRIDE_ENV`] set -> that directory is authoritative instead of the sibling
//!   checkout. A directory that doesn't exist is always a panic: an explicit request that cannot
//!   be satisfied is an error, never a skip.
//!
//! [`resolve_from`] holds all three decisions as a pure function of its two explicit inputs, so a
//! plain executed `#[test]` (see `domain_outbox_builders.rs`, the one consuming binary that
//! carries this module's own tests) can drive every branch -- including the standalone one --
//! against temp directories, without needing a real standalone checkout or mutating the env var.
//! [`resolve_fixture_set_dir`] is the thin wrapper that reads the real env var and the real
//! sibling root and delegates to it.

use std::path::Path;
use std::path::PathBuf;

/// Set this to an explicit fixture-set directory to bypass sibling-repo discovery entirely (e.g.
/// to prove the resolver itself, or to run these tests in a standalone checkout that has a copy
/// of the fixtures some other way). See the module doc for the override's own fail-hard contract.
pub const FIXTURE_DIR_OVERRIDE_ENV: &str = "LORE_NOTIFICATION_PLANE_FIXTURES";

/// Where the `lore-notification-plane` fixture set was found, or the discovered fact that it
/// cannot be found because this is a standalone checkout.
pub enum FixtureSetLocation {
    /// A concrete directory to read named fixture files from. The caller still owns checking that
    /// a specific named file within it exists and panicking (not skipping) if it doesn't --
    /// resolving to a `Directory` here is a promise about the checkout's shape, not about any one
    /// file's presence.
    Directory(PathBuf),
    /// No sibling `lorehub` repo root exists at all. The caller must skip.
    Standalone { searched: PathBuf },
}

/// Pure resolution decision, taking both inputs explicitly rather than reading the environment or
/// the real filesystem layout itself. This is what makes every branch -- including the standalone
/// one, which touching the real tree can't safely exercise here -- provable by a plain executed
/// test against disposable temp directories.
///
/// Resolution order: (1) `override_dir` if `Some` -- panics if it is not an existing directory;
/// (2) otherwise `lorehub_root`: [`FixtureSetLocation::Standalone`] if it doesn't exist, or the
/// fixture-set directory shape beneath it (`docs/contracts/fixtures/lore-notification-plane`)
/// otherwise -- even if nothing exists at that deeper path yet. An existing sibling repo root with
/// an absent fixture set underneath it is fixture drift, not a standalone checkout, and must never
/// be reported as `Standalone`.
pub fn resolve_from(override_dir: Option<PathBuf>, lorehub_root: PathBuf) -> FixtureSetLocation {
    if let Some(dir) = override_dir {
        if !dir.is_dir() {
            panic!(
                "{FIXTURE_DIR_OVERRIDE_ENV} was set to {dir:?}, which is not a directory. An \
                 explicit fixture-directory override that cannot be satisfied is a hard failure, \
                 never a skip."
            );
        }
        return FixtureSetLocation::Directory(dir);
    }

    if !lorehub_root.is_dir() {
        return FixtureSetLocation::Standalone {
            searched: lorehub_root,
        };
    }
    FixtureSetLocation::Directory(
        lorehub_root
            .join("docs")
            .join("contracts")
            .join("fixtures")
            .join("lore-notification-plane"),
    )
}

/// Resolve the `lore-notification-plane` fixture-set directory against the real environment
/// variable and the real sibling checkout layout. See [`resolve_from`] for the resolution rules
/// themselves.
pub fn resolve_fixture_set_dir() -> FixtureSetLocation {
    let override_dir = std::env::var(FIXTURE_DIR_OVERRIDE_ENV)
        .ok()
        .map(PathBuf::from);
    resolve_from(override_dir, sibling_lorehub_root())
}

/// `lorehub/` relative to this crate's manifest dir -- sibling checkouts under one
/// `lorehub-all` container: `<crate>/../../lorehub`.
fn sibling_lorehub_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("lorehub")
}

/// Print the one loud, greppable skip line a standalone checkout's test must emit before
/// returning early. `test_name` should be the fully qualified `module::test_fn` the notice is
/// for, so a scrollback search for "SKIP" names exactly which test never ran its assertions.
pub fn print_standalone_skip_notice(test_name: &str, searched: &Path) {
    println!(
        "SKIP {test_name}: no sibling `lorehub` checkout found at {searched:?} -- this looks \
         like a standalone checkout (e.g. an upstream contributor's clone) with no \
         lore-notification-plane fixtures available. Set {FIXTURE_DIR_OVERRIDE_ENV}=<dir> \
         (pointing at a directory containing the required fixture files) to run this test \
         against an explicit fixture set instead."
    );
}
