// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The one WP-118 Phase 4 rule this crate still has to hold with a source scan.
//!
//! # Why this file shrank
//!
//! The provider seam moved to `lore-fragment-provider`, and with it most of what
//! this file used to check. `lore-postgres` no longer depends on
//! `lore-object-dispatch`, so nothing here can name
//! `GovernedProviderClient::execute`'s parameter types and therefore nothing
//! here can call it — the alias scans, accessor scans, re-export scans and the
//! scaffolding they needed were all guarding a property the compiler now holds,
//! and they were deleted rather than carried. The seam's own remaining rules
//! live in `lore-fragment-provider/tests/seam_source_pins.rs`.
//!
//! What is left is CR-031's no-private-provider-client rule for the five files
//! that stayed: `coordinator.rs`, `masks.rs`, `mod.rs`, `schema.rs` and
//! `states.rs`. That cannot be a dependency-graph fact here, because this crate
//! legitimately depends on `aws-sdk-s3` for the legacy CR-007 immutable store.
//! It is a scan over five files that construct no provider client at all — a far
//! smaller surface than the package-wide version it replaces, and the honest
//! statement is that it is regression detection, not a proof.
//!
//! `provider.rs` is exempt and listed as such: it is an adapter of ~90 lines
//! that names the seam crate and nothing else.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// The files this rule covers — every package file but one. `provider.rs` is
/// deliberately absent, and it is the ONLY exemption: it holds
/// only re-exports and the `DomainError` conversion, and it cannot reach a
/// provider because this crate cannot name the types that would let it.
const SCANNED_FILES: [&str; 5] = [
    "coordinator.rs",
    "masks.rs",
    "mod.rs",
    "schema.rs",
    "states.rs",
];

/// Every `.rs` file expected in the package, so a new one cannot appear and
/// escape the scan by not being listed.
const PACKAGE_FILES: [&str; 6] = [
    "coordinator.rs",
    "masks.rs",
    "mod.rs",
    "provider.rs",
    "schema.rs",
    "states.rs",
];

/// A provider SDK or bucket client.
///
/// **`lore_aws` as a whole is deliberately not on this list, and the carve-out
/// is load-bearing.** `masks.rs` compares against
/// `lore_aws::store::object_metadata::PAYLOAD_FLAGS`, the shared payload-flag
/// vocabulary CR-031's two masks are defined against — a constant, not a
/// client, and a dependency this package inherited rather than introduced.
/// Forbidding the crate outright would fail on that line and invite the rule to
/// be weakened wholesale, so the client surface is named instead.
const PRIVATE_CLIENT_TOKENS: [&str; 9] = [
    "aws_sdk_s3",
    "aws-sdk-s3",
    "aws_smithy",
    "aws_config",
    "lore_aws::clients",
    "lore_aws::s3",
    "S3Impl",
    "ObjectStoreSettings",
    "PostgresImmutableStore",
];

fn package_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain/fragments")
}

fn read(file: &str) -> String {
    let path = package_dir().join(file);
    match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => panic!("{} must be readable: {error}", path.display()),
    }
}

/// Removes `//` comments, keeping any line that contains a `"` whole so a string
/// literal cannot hide code behind a comment marker.
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                return "";
            }
            if line.contains('"') {
                return line;
            }
            match line.find("//") {
                Some(index) => &line[..index],
                None => line,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn hits<'a>(haystack: &str, tokens: &[&'a str]) -> Vec<&'a str> {
    tokens
        .iter()
        .copied()
        .filter(|token| haystack.contains(token))
        .collect()
}

/// The five scanned files build no private provider client.
#[test]
fn the_remaining_package_files_build_no_private_provider_client() {
    for file in SCANNED_FILES {
        let found = hits(&strip_line_comments(&read(file)), &PRIVATE_CLIENT_TOKENS);
        assert!(
            found.is_empty(),
            "{file} names {found:?}; WP-114's governed client is the only route to a bucket",
        );
    }
}

/// The scan must actually be over code, not over prose. Checked against the real
/// file: an injected `use` line is caught, the same token in a comment is not,
/// and a string literal containing a comment marker does not hide the code after
/// it.
#[test]
fn the_scanner_catches_code_and_ignores_prose() {
    let coordinator = strip_line_comments(&read("coordinator.rs"));
    for token in PRIVATE_CLIENT_TOKENS {
        for injected in [
            format!("use {token};"),
            format!("let marker = \"//\"; use {token};"),
        ] {
            let mutated = format!("{coordinator}\n{injected}\n");
            let survivor = strip_line_comments(&mutated)
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or_default()
                .to_string();
            assert!(
                survivor.contains(token),
                "the scanner must catch {token} written as code, got {survivor:?}",
            );
        }
        let as_comment = format!("{coordinator}\n// mentions {token} SENTINELXYZ\n");
        assert!(
            !strip_line_comments(&as_comment).contains("SENTINELXYZ"),
            "the scanner must ignore {token} written in a comment",
        );
    }
}

/// The scanned set must be the package's actual contents, so a new file cannot
/// appear and escape the rule by not being listed. `mod.rs`'s declarations must
/// agree, so a file cannot be compiled from somewhere the scan never reads.
#[test]
fn the_scanned_file_list_is_what_the_package_compiles() {
    let entries = match fs::read_dir(package_dir()) {
        Ok(entries) => entries,
        Err(error) => panic!("the package directory must be readable: {error}"),
    };
    let mut found = Vec::new();
    for entry in entries.filter_map(|entry| entry.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                panic!("domain/fragments/ has a subdirectory ({name}); this guard is flat")
            }
            _ => {}
        }
        if name.ends_with(".rs") {
            found.push(name);
        }
    }
    found.sort();
    assert_eq!(
        found,
        PACKAGE_FILES.map(str::to_string).to_vec(),
        "every .rs file in domain/fragments/ must be listed in PACKAGE_FILES",
    );

    let mut declared: Vec<String> = strip_line_comments(&read("mod.rs"))
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let name = trimmed
                .strip_prefix("pub mod ")
                .or_else(|| trimmed.strip_prefix("mod "))?;
            name.strip_suffix(';').map(|name| format!("{name}.rs"))
        })
        .collect();
    declared.push("mod.rs".to_string());
    declared.sort();
    assert_eq!(
        declared,
        PACKAGE_FILES.map(str::to_string).to_vec(),
        "mod.rs's module declarations must match the scanned file list exactly",
    );

    // Every package file is scanned except the ones this list names, and the
    // list is derived rather than hardcoded.
    //
    // **An earlier revision hardcoded `*file != "mod.rs"` into this filter and
    // then asserted the remainder was `["provider.rs"]`, so it reported one
    // exemption while silently having two.** A private `aws_sdk_s3::Client` in
    // `mod.rs` passed the whole suite. `mod.rs` is scanned now, so the assertion
    // and the reality agree, and adding an exemption means editing this list
    // where a reader will see it.
    let exempt: Vec<&str> = PACKAGE_FILES
        .iter()
        .copied()
        .filter(|file| !SCANNED_FILES.contains(file))
        .collect();
    assert_eq!(
        exempt,
        vec!["provider.rs"],
        "provider.rs is the only file exempt from the private-client scan",
    );
}

/// `include!` and `#[path]` would compile source this scan never reads.
#[test]
fn the_package_splices_in_no_source_from_outside_itself() {
    for file in PACKAGE_FILES {
        let found = hits(&strip_line_comments(&read(file)), &["include!", "#[path"]);
        assert!(
            found.is_empty(),
            "{file} names {found:?}, which compiles source this guard never reads",
        );
    }
}
