// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): a canary for the query depth of the client futures an embedder awaits.
//!
//! rustc lays out an async block's state machine by recursing through every future it awaits.
//! When the nesting is deeper than the crate's `recursion_limit` (128 by default), the build
//! fails with "queries overflow the depth limit!". The failure shows up in the crate that awaits
//! the future, not in `lore`. lorehub-desktop's `import_adopt_online_smoke` test awaits a clone
//! through its own wrappers. It needed 129 after lore `a5f5e608` and needs 124 after `098243de`.
//!
//! This crate lowers its own limit so that it fails first. Measured with `CARGO_INCREMENTAL=0`,
//! the clone is the deepest entry below. It needs 104 at `233f4ef0`, 110 at `a5f5e608` and 105 at
//! `098243de`. The desktop test needs 123, 129 and 124 at the same commits: 19 levels more each
//! time. So the limit is 106. This crate fails when the desktop test would need 126 or more, two
//! levels before the desktop's limit of 128 breaks. Today it has one level to spare.
//!
//! When this fails, box the new async state at an existing seam (`Box::pin`, as `098243de` does in
//! `bounded_if_unmanaged`). Do not raise the limit here unless the desktop path has moved and you
//! have measured it again.
//!
//! `cargo test` builds this with `[profile.test]`, which sets `incremental = false`, so it measures
//! cold. `cargo clippy` uses the `dev` profile, which is incremental. With `098243de`'s box removed,
//! a cold clippy fails here, but an incremental clippy that first ran green at `098243de` stayed
//! green. Do not trust an incremental build for this check.
//!
//! The offset of 19 is measured for the desktop's clone path only. The block covers the entries the
//! desktop's commit, clone, sync and push paths await. It does not cover lock, merge or metadata
//! entries; if one of those becomes the deepest, add it here and measure again.
//!
//! The test only builds the future. It never polls it, so it does no I/O.

#![recursion_limit = "106"]

use lore::branch::LoreBranchPushArgs;
use lore_revision::interface::LoreGlobalArgs;

fn push_args() -> LoreBranchPushArgs {
    LoreBranchPushArgs {
        branch: Default::default(),
        fast_forward_merge: 0,
    }
}

/// The public entries lorehub-desktop's engine awaits, in one block. The depth is the deepest of
/// them; today that is the clone.
#[test]
fn client_futures_stay_below_the_desktop_query_depth() {
    let future = async {
        lore::repository::clone(LoreGlobalArgs::default(), Default::default(), None).await;
        lore::revision::commit(LoreGlobalArgs::default(), Default::default(), None).await;
        lore::revision::commit_with_managed_uploads(
            LoreGlobalArgs::default(),
            Default::default(),
            None,
        )
        .await;
        lore::revision::sync(LoreGlobalArgs::default(), Default::default(), None).await;
        lore::revision::sync_verified_remote(LoreGlobalArgs::default(), Default::default(), None)
            .await;
        lore::branch::push(LoreGlobalArgs::default(), push_args(), None).await;
        lore::branch::push_managed(LoreGlobalArgs::default(), push_args(), None, None).await;
        lore::branch::push_with_attempt_store(
            LoreGlobalArgs::default(),
            push_args(),
            None,
            std::sync::Arc::new(lore_transport::attempt_store::VolatileAttemptStore::new()),
        )
        .await;
    };
    // Building the block is enough: rustc lays its state machine out when it compiles this
    // function, and that is the query that overflows. The test never polls the future.
    drop(future);
}
