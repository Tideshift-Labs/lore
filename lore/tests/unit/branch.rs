// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore::branch::*;
use lore::interface::LoreEventCallback;
use lore::interface::LoreString;
use lore_base::error::InvalidArguments;
use lore_error_set::FfiError;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreGlobalArgs;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptStore;

use crate::call_delegation::service_env_child;

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
/// An old client's payload is this one without the field it never knew, so
/// it is built by removing the field rather than by transcribing the shape.
fn without_inherit_metadata<T: serde::Serialize>(args: &T) -> serde_json::Value {
    let mut payload = serde_json::to_value(args).expect("args must serialise");
    payload
        .as_object_mut()
        .expect("args serialise to an object")
        .remove("inherit_metadata")
        .expect("the field must be present before it is removed");
    payload
}

#[test]
fn merge_start_args_old_payload_missing_inherit_metadata_uses_default() {
    // Old IPC client payload with no inherit_metadata field. The new field
    // must be `#[serde(default)]` so old clients keep working.
    let payload = without_inherit_metadata(&LoreBranchMergeStartArgs {
        branch: "feature".into(),
        message: "merge feature".into(),
        no_commit: 0,
        link: Default::default(),
        ignore_links: 0,
        inherit_metadata: LoreArray::from_vec(vec![LoreString::from("change-request")]),
    });

    let args: LoreBranchMergeStartArgs =
        serde_json::from_value(payload).expect("old payload must deserialise");

    assert_eq!(args.branch.as_str(), "feature");
    assert_eq!(args.message.as_str(), "merge feature");
    assert!(args.inherit_metadata.as_slice().is_empty());
}

#[test]
fn merge_into_args_old_payload_missing_inherit_metadata_uses_default() {
    let payload = without_inherit_metadata(&LoreBranchMergeIntoArgs {
        branch: "main".into(),
        branch_id: Default::default(),
        message: "merge into main".into(),
        link: Default::default(),
        ignore_links: 0,
        inherit_metadata: LoreArray::from_vec(vec![LoreString::from("*")]),
    });

    let args: LoreBranchMergeIntoArgs =
        serde_json::from_value(payload).expect("old payload must deserialise");

    assert_eq!(args.branch.as_str(), "main");
    assert!(args.inherit_metadata.as_slice().is_empty());
}

#[test]
fn archive_args_old_payload_missing_cascade_fields_uses_defaults() {
    // Old IPC client payload with no layer or link fields. The new fields
    // must be `#[serde(default)]` so old clients keep working.
    let payload = r#"{ "branch": "feature" }"#;

    let args: LoreBranchArchiveArgs =
        serde_json::from_str(payload).expect("old payload must deserialise");

    assert_eq!(args.branch.as_str(), "feature");
    assert_eq!(args.layer.as_str(), "");
    assert_eq!(args.include_layers, 0);
    assert_eq!(args.link.as_str(), "");
    assert_eq!(args.include_links, 0);
}

#[test]
fn archive_args_layer_payload_missing_link_fields_uses_defaults() {
    // A client that knows the layer fields but not the link ones.
    let payload = r#"{ "branch": "feature", "layer": "lay", "include_layers": 1 }"#;

    let args: LoreBranchArchiveArgs =
        serde_json::from_str(payload).expect("layer payload must deserialise");

    assert_eq!(args.layer.as_str(), "lay");
    assert_eq!(args.include_layers, 1);
    assert_eq!(args.link.as_str(), "");
    assert_eq!(args.include_links, 0);
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
