// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Compile-fail proof for WP-114 CD-8's bound provider-attempt audit: no external crate can
//! construct a `BoundProviderAttemptAudit` as a struct literal, and `ObjectStoreCompactReceiptInput`
//! cannot accept a bare `ObjectStoreProviderAttemptAudit` in its place.

use std::path::PathBuf;
use std::process::Command;

fn run_compile_fail_case(binary: &str) -> (bool, String) {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/compile_fail/get_only_rejects_metered/Cargo.toml");
    let target = std::env::temp_dir().join(format!(
        "lore-object-dispatch-bound-audit-compile-fail-{binary}-{}",
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
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn bound_provider_attempt_audit_has_no_public_constructor() {
    let (succeeded, stderr) =
        run_compile_fail_case("bound-provider-attempt-audit-cannot-be-constructed");
    assert!(
        !succeeded,
        "an empty BoundProviderAttemptAudit struct literal unexpectedly compiled"
    );
    assert!(
        stderr.contains("cannot construct `BoundProviderAttemptAudit` with struct literal syntax"),
        "wrong diagnostic -- expected rustc's private-field construction refusal:\n{stderr}"
    );
    assert!(
        stderr.contains("private fields"),
        "diagnostic did not name this as a privacy refusal:\n{stderr}"
    );
}

#[test]
fn compact_receipt_input_rejects_an_unbound_provider_attempt_audit() {
    let (succeeded, stderr) = run_compile_fail_case("compact-receipt-input-rejects-unbound-audit");
    assert!(
        !succeeded,
        "a bare ObjectStoreProviderAttemptAudit unexpectedly satisfied provider_attempt_audit"
    );
    assert!(
        stderr.contains("error[E0308]"),
        "wrong diagnostic class -- expected a type mismatch:\n{stderr}"
    );
    assert!(
        stderr.contains("ObjectStoreProviderAttemptAudit")
            && stderr.contains("BoundProviderAttemptAudit"),
        "diagnostic did not name both the offered and required audit types:\n{stderr}"
    );
}
