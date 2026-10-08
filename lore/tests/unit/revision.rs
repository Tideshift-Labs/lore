// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore::interface::LoreString;
use lore::revision::*;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreGlobalArgs;

#[test]
fn cherry_pick_args_old_payload_missing_inherit_metadata_uses_default() {
    // Old IPC client payload with no inherit_metadata field. The new field
    // must be `#[serde(default)]` so old clients keep working.
    let full = LoreRevisionCherryPickArgs {
        revision: "main@3".into(),
        message: "pick".into(),
        no_commit: 0,
        inherit_metadata: LoreArray::from_vec(vec![LoreString::from("change-request")]),
    };
    let mut payload = serde_json::to_value(&full).expect("args must serialise");
    payload
        .as_object_mut()
        .expect("args serialise to an object")
        .remove("inherit_metadata")
        .expect("the field must be present before it is removed");

    let args: LoreRevisionCherryPickArgs =
        serde_json::from_value(payload).expect("old payload must deserialise");

    assert_eq!(args.revision.as_str(), "main@3");
    assert_eq!(args.message.as_str(), "pick");
    assert!(args.inherit_metadata.as_slice().is_empty());
}

#[test]
fn sync_args_old_payload_missing_view_uses_default() {
    // Old IPC client payload with no view field. The new field must be
    // `#[serde(default)]` so old clients keep working.
    let full = LoreRevisionSyncArgs {
        revision: "main@3".into(),
        view: "views/engine.filter".into(),
        ..Default::default()
    };
    let mut payload = serde_json::to_value(&full).expect("args must serialise");
    payload
        .as_object_mut()
        .expect("args serialise to an object")
        .remove("view")
        .expect("the field must be present before it is removed");

    let args: LoreRevisionSyncArgs =
        serde_json::from_value(payload).expect("old payload must deserialise");

    assert_eq!(args.revision.as_str(), "main@3");
    assert!(
        args.view.is_empty(),
        "an omitted view keeps the view the instance holds"
    );
}

#[test]
fn commit_args_old_payload_missing_layer_fields_uses_defaults() {
    // Old IPC client payload with no layer_* fields. The new fields must be
    // `#[serde(default)]` so old clients keep working.
    let payload = r#"{
            "message": "main",
            "link": "",
            "link_paths": [],
            "link_messages": []
        }"#;

    let args: LoreRevisionCommitArgs =
        serde_json::from_str(payload).expect("old payload must deserialise");

    assert_eq!(args.message.as_str(), "main");
    assert_eq!(args.link.as_str(), "");
    assert_eq!(args.layer.as_str(), "");
    assert!(args.layer_paths.as_slice().is_empty());
    assert!(args.layer_messages.as_slice().is_empty());
}

#[test]
fn commit_args_new_payload_carries_layer_fields() {
    let payload = r#"{
            "message": "main",
            "link": "",
            "link_paths": [],
            "link_messages": [],
            "layer": "external/lib",
            "layer_paths": ["external/lib"],
            "layer_messages": ["layer-specific message"]
        }"#;

    let args: LoreRevisionCommitArgs =
        serde_json::from_str(payload).expect("new payload must deserialise");

    assert_eq!(args.layer.as_str(), "external/lib");
    assert_eq!(args.layer_paths.as_slice().len(), 1);
    assert_eq!(args.layer_paths.as_slice()[0].as_str(), "external/lib");
    assert_eq!(args.layer_messages.as_slice().len(), 1);
    assert_eq!(
        args.layer_messages.as_slice()[0].as_str(),
        "layer-specific message"
    );
}

/// A command runs in its handler's future, with no future around it holding the arguments
/// again.
#[test]
fn a_command_runs_in_its_handlers_future() {
    let handler = commit_local(
        LoreGlobalArgs::default(),
        LoreRevisionCommitArgs::default(),
        None,
    );
    let command = lore::args::InvokableLoreArgs::invoke_local(
        LoreRevisionCommitArgs::default(),
        LoreGlobalArgs::default(),
        None,
    );

    assert_eq!(size_of_val(&command), size_of_val(&handler));
}
