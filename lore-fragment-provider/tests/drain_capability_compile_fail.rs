// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Narrow-by-construction proof for WP-114 CD-6's `FragmentDrainCapability`
//! (tranche D-L3-2), modelled on `direct_put_compile_fail.rs`.
//!
//! Each fixture is one claim: a caller holding the capability cannot reach
//! the pool, the dispatch client, the gateway, or the entry through any
//! accessor, and the attempt type it accepts cannot name a traffic class, an
//! attempt class, a declared size, a declared hash, or a target. The
//! structural authority for these claims is `seam_source_pins.rs`'s
//! exhaustive method-set and declaration-shape pins (Rule 5); this file
//! demonstrates the actual compiler diagnostic each one produces.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn drain_capability_is_narrow_by_construction() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lore-object-dispatch/tests/compile_fail/get_only_rejects_metered/Cargo.toml");
    for (binary, expectations) in [
        (
            "drain-capability-no-internal-accessor",
            vec![
                "no method named `pool`",
                "no method named `dispatch`",
                "no method named `gateway`",
                "no method named `entry`",
            ],
        ),
        (
            "drain-attempt-cannot-name-forbidden-fields",
            vec![
                "no field `traffic_class`",
                "no field `attempt_class`",
                "no field `declared_size`",
                "no field `declared_blake3`",
                "no field `target`",
            ],
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
        for diagnostic in &expectations {
            assert!(
                stderr.contains(diagnostic),
                "{binary}: missing {diagnostic:?}:\n{stderr}"
            );
        }
    }
}
