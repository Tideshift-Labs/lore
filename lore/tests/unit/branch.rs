// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore::branch::*;
use lore::interface::LoreEventCallback;
use lore::interface::LoreString;
use lore_base::error::Disconnected;
use lore_base::error::InvalidArguments;
use lore_base::error::NotAuthenticated;
use lore_base::error::NotAuthorized;
use lore_error_set::FfiError;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::repository::RemoteState;
use lore_revision::test_util::context_with_state;
use lore_transport::ProtocolError;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptStore;

use crate::call_delegation::service_env_child;
use crate::storage::under_globals;

mod managed_service_tests;

// FORK-LOCAL (Tideshift, WP-120): the attempt-store push refusal, moved from `src/branch.rs`
// with the upstream unit-test relocation.
//
// Accepted as a source-level fact, not tested: `push` (via `push_local`) still reaches
// `push_journalled` with `None`, exactly as it did before `push_with_attempt_store` existed.
// The claim is one literal at one call site (`push_local`'s `push_journalled(globals, args,
// callback, None)`, in `src/branch.rs`). Getting it wrong costs an extra attempt record, not
// lost correctness -- the cheap direction of that failure -- so it does not earn a live tier.
// Ruled by team-lead and the receipt-client-binding lane, 2026-09.
//
// The reason recorded here in that ruling -- that no live-connected `RepositoryContext`
// fixture existed anywhere in this codebase -- no longer holds. One exists now
// (`lore_revision::live_fixture`), and the sibling claim it was blocking, that
// `push_with_attempt_store` forwards the store it was given, is proven against it in
// `lore/tests/live_push_journal.rs`. This literal is still not worth a live test, but for the
// reason above rather than for want of a fixture.

/// The same status shape `lore::call_delegation::reject_call` uses for every other
/// pre-command rejection, so this refusal cannot be told apart from one of those by a
/// caller inspecting the status alone.
fn undelegatable_status() -> i32 {
    InvalidArguments {
        reason: String::new(),
    }
    .ffi_code()
}

fn no_callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}

/// `push_with_attempt_store` must refuse under `LORE_USE_SERVICE` rather than delegate --
/// see the function's own doc comment for why a delegated push would strand the caller's
/// journal. The repository path is deliberately nonexistent and the store deliberately
/// records every call it receives: either one being touched would mean the refusal ran too
/// late, after the code had already started the operation it exists to prevent.
#[test]
fn push_with_attempt_store_refuses_when_delegation_is_requested() {
    if !service_env_child(
        "branch::push_with_attempt_store_refuses_when_delegation_is_requested",
        &[Some("1")],
    ) {
        return;
    }

    let globals = LoreGlobalArgs {
        repository_path: LoreString::from_str(
            "Z:/lore-push-with-attempt-store-test-nonexistent-9f3c2a",
        ),
        ..LoreGlobalArgs::default()
    };
    let args = LoreBranchPushArgs {
        branch: LoreString::default(),
        fast_forward_merge: 0,
    };
    let store = Arc::new(VolatileAttemptStore::new());
    let attempts: Arc<dyn AttemptStore> = store.clone();

    let status = lore::runtime().block_on(push_with_attempt_store(
        globals,
        args,
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        undelegatable_status(),
        "the refusal must use the same status shape every other pre-command rejection uses"
    );
    assert!(
        lore::runtime()
            .block_on(store.unresolved())
            .expect("unresolved() must succeed on a fresh store")
            .is_empty(),
        "the attempt store must never be touched when the call is refused before it runs"
    );
}

#[test]
fn cascade_scope_maps_each_field_combination() {
    assert!(matches!(
        CascadeScope::new(&LoreString::from(""), 0, "link", "include_links"),
        Ok(CascadeScope::OuterOnly)
    ));
    assert!(matches!(
        CascadeScope::new(&LoreString::from(""), 1, "link", "include_links"),
        Ok(CascadeScope::All)
    ));
    assert!(matches!(
        CascadeScope::new(&LoreString::from("lnk"), 0, "link", "include_links"),
        Ok(CascadeScope::Single(path)) if path == "lnk"
    ));
}

#[test]
fn cascade_scope_rejects_a_path_together_with_include_all() {
    let scope = CascadeScope::new(&LoreString::from("lnk"), 1, "link", "include_links");

    let err = scope.expect_err("a path with include_all must be refused");
    assert!(
        err.to_string().contains("link and include_links"),
        "expected the conflicting fields to be named, got: {err}"
    );
}

/// `lore branch metadata set --branch` fails with the remote's refusal of the branch lookup, and
/// with `InvalidArguments` where the remote cannot be reached.
#[tokio::test]
async fn metadata_set_fails_with_a_refused_branch_lookup() {
    let invalid_arguments = InvalidArguments {
        reason: String::new(),
    }
    .ffi_code();
    let mut differing = Vec::new();
    for (failure, expected) in [
        (
            ProtocolError::from(NotAuthenticated::new(lore_base::error::UNSTATED_REFUSAL)),
            NotAuthenticated::FFI_CODE,
        ),
        (ProtocolError::from(NotAuthorized), NotAuthorized.ffi_code()),
        (ProtocolError::from(Disconnected), invalid_arguments),
    ] {
        let described = format!("{failure:?}");
        let set = under_globals(LoreGlobalArgs::default(), async move {
            let repository = context_with_state(RemoteState::Failed(failure)).await;
            metadata_set_impl(
                repository,
                LoreBranchMetadataSetArgs {
                    branch: LoreString::from("refused"),
                    ..Default::default()
                },
            )
            .await
        })
        .await;
        if set.as_ref().err().map(FfiError::ffi_code) != Some(expected) {
            differing.push(format!("{described}: got {set:?}"));
        }
    }
    assert!(differing.is_empty(), "{differing:#?}");
}
