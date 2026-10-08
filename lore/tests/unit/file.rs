// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore::file::*;

#[test]
fn reset_to_last_merged_args_old_payload_missing_merge_side_uses_default() {
    // Old IPC client payload with no merge_side field. The new field must be
    // `#[serde(default)]` so old clients keep working.
    let payload = r#"{ "paths": [], "branch": "main", "purge": 0 }"#;

    let args: LoreFileResetToLastMergedArgs =
        serde_json::from_str(payload).expect("old payload must deserialise");

    assert_eq!(args.branch.as_str(), "main");
    assert_eq!(args.merge_side, 0);
}
