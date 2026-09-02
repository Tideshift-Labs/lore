// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Compile-fail proof that the direct PUT request cannot represent another provider operation.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn a_direct_put_request_cannot_name_head_or_any_other_attempt_class() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/compile_fail/get_only_rejects_metered/Cargo.toml");
    let target = std::env::temp_dir().join(format!(
        "lore-object-dispatch-direct-put-compile-fail-{}",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(&fixture)
        .args(["--bin", "direct-put-cannot-name-attempt-class"])
        .arg("--target-dir")
        .arg(&target)
        .output()
        .expect("compile-fail fixture must run cargo check");
    let _ = std::fs::remove_dir_all(&target);

    assert!(
        !output.status.success(),
        "a direct PUT request with a HEAD class unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error[E0560]"),
        "wrong diagnostic class:\n{stderr}"
    );
    assert!(
        stderr.contains("ProviderDirectPutAttemptRequest")
            && stderr.contains("has no field named `attempt_class`"),
        "diagnostic did not prove the direct request has no operation-class field:\n{stderr}"
    );
}
