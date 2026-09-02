// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::PathBuf;
use std::process::Command;

#[test]
fn direct_put_requires_admission_and_a_put_specific_token() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lore-object-dispatch/tests/compile_fail/get_only_rejects_metered/Cargo.toml");
    for (binary, receiver, method) in [
        (
            "fragment-put-before-admission",
            "FragmentProviderGateway",
            "execute_direct_put",
        ),
        (
            "fragment-general-token-cannot-put",
            "AdmittedFragmentAttempt",
            "execute_direct_put",
        ),
    ] {
        let target = std::env::temp_dir().join(format!(
            "lore-fragment-provider-{binary}-{}",
            std::process::id()
        ));
        let output = Command::new(env!("CARGO"))
            .args(["check", "--offline", "--quiet", "--manifest-path"])
            .arg(&fixture)
            .args(["--bin", binary])
            .arg("--target-dir")
            .arg(&target)
            .output()
            .expect("compile-fail fixture must run cargo check");
        let _ = std::fs::remove_dir_all(&target);
        assert!(!output.status.success(), "{binary} unexpectedly compiled");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("error[E0599]"),
            "{binary}: wrong diagnostic:\n{stderr}"
        );
        assert!(
            stderr.contains(receiver) && stderr.contains(&format!("no method named `{method}`")),
            "{binary}: diagnostic did not prove the receiver lacks the PUT method:\n{stderr}"
        );
    }
}
