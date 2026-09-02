// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Compile-fail proof that the GET-only entry cannot accept a metered operation request.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn a_metered_non_get_request_cannot_enter_execute_get() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/compile_fail/get_only_rejects_metered/Cargo.toml");
    let target = std::env::temp_dir().join(format!(
        "lore-object-dispatch-get-compile-fail-{}",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(&fixture)
        .arg("--target-dir")
        .arg(&target)
        .output()
        .expect("compile-fail fixture must run cargo check");
    let _ = std::fs::remove_dir_all(&target);

    assert!(
        !output.status.success(),
        "non-GET request unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error[E0308]"),
        "wrong diagnostic class:\n{stderr}"
    );
    assert!(
        stderr.contains("expected `&ProviderGetAttemptRequest`")
            && stderr.contains("found `&MeteredProviderAttemptRequest`"),
        "diagnostic did not prove the GET-only type boundary:\n{stderr}"
    );
}
