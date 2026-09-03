// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The WP-118 rules this crate has to hold with a source scan rather than with
//! the compiler: CR-031's no-private-provider-client rule, and the failpoint
//! anchor-name rule (see "Why the anchor scan lives here" below).
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
//! What is left is CR-031's no-private-provider-client rule for the six files
//! that stayed: `coordinator.rs`, `failpoints.rs`, `masks.rs`, `mod.rs`,
//! `schema.rs` and `states.rs`. That cannot be a dependency-graph fact here,
//! because this crate legitimately depends on `aws-sdk-s3` for the legacy CR-007
//! immutable store. It is a scan over six files that construct no provider
//! client at all — a far smaller surface than the package-wide version it
//! replaces, and the honest statement is that it is regression detection, not a
//! proof.
//!
//! `failpoints.rs` is compiled only under the `failure_generator` feature
//! (`mod.rs` gates its `pub mod` declaration), but this scan reads the package
//! directory from disk, so the file is covered in a default build too. That is
//! deliberate: a feature-gated file is still source in the tree, and a private
//! provider client in one would otherwise be invisible to every default run.
//!
//! `provider.rs` is exempt and listed as such: it is an adapter of ~90 lines
//! that names the seam crate and nothing else.
//!
//! # Why the anchor scan lives here
//!
//! A `failpoint!("...")` anchor name is checked against `failpoints.rs`'s
//! `ANCHORS` table by that module's own
//! `the_anchor_table_and_the_call_sites_name_the_same_set` — which compiles
//! **only** under `--features failure_generator`, and CI never runs the test
//! suite with that feature (`.github/workflows/pr-validate.yml:194-198` only
//! *builds* with it). The macro's default arm (`mod.rs`'s
//! `#[cfg(not(feature = "failure_generator"))]` branch) binds the anchor to a
//! `&'static str` and discards it, so it type-checks the expression and never
//! the name. A mistyped anchor therefore compiles clean and reaches no gate at
//! all: the call site silently stops being reachable through `hit`, because the
//! configuration parser drops a name with no `ANCHORS` entry.
//!
//! This file already reads the package directory from disk in the default tier,
//! so it can hold both files as text with the module cfg-stripped. That makes it
//! the one place the rule can be enforced in the tier that actually runs.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// The files this rule covers — every package file but one. `provider.rs` is
/// deliberately absent, and it is the ONLY exemption: it holds
/// only re-exports and the `DomainError` conversion, and it cannot reach a
/// provider because this crate cannot name the types that would let it.
const SCANNED_FILES: [&str; 6] = [
    "coordinator.rs",
    "failpoints.rs",
    "masks.rs",
    "mod.rs",
    "schema.rs",
    "states.rs",
];

/// Every `.rs` file expected in the package, so a new one cannot appear and
/// escape the scan by not being listed.
const PACKAGE_FILES: [&str; 7] = [
    "coordinator.rs",
    "failpoints.rs",
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

/// The six scanned files build no private provider client.
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

/// String literals in `text`, in source order.
///
/// Sound only where no literal contains an escaped quote; the caller asserts
/// that before relying on this. A `\`-continued literal spanning several lines
/// is handled, because it still holds no inner `"`.
fn string_literals(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else {
            break;
        };
        found.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    found
}

/// An anchor name is a dotted lowercase path. A description is prose, so this
/// separates the two halves of an `ANCHORS` entry even if the pair parse below
/// ever slips out of step.
fn is_anchor_shaped(name: &str) -> bool {
    name.contains('.')
        && !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// The anchor names declared in `failpoints.rs`'s `ANCHORS` table, parsed as
/// text so the table is readable with the module's feature off.
fn declared_anchors() -> Vec<String> {
    let source = strip_line_comments(&read("failpoints.rs"));
    const OPEN: &str = "const ANCHORS: &[(&str, &str)] = &[";
    let start = match source.find(OPEN) {
        Some(index) => index + OPEN.len(),
        None => panic!("failpoints.rs must declare {OPEN}; this scan is broken, not the code"),
    };
    let body = &source[start..];
    let end = match body.find("\n];") {
        Some(index) => index,
        None => panic!("the ANCHORS table must be terminated; this scan is broken, not the code"),
    };
    let table = &body[..end];

    // A `\`-continued description is fine and common here; an escaped quote is
    // not, because it would end a literal early and desync the pair parse. The
    // shape check below is the backstop, this is the direct statement.
    assert!(
        !table.contains("\\\""),
        "the ANCHORS table gained an escaped quote, so the pair parse below is no longer sound",
    );
    let literals = string_literals(table);
    assert!(
        !literals.is_empty() && literals.len().is_multiple_of(2),
        "the ANCHORS table must parse as (anchor, description) pairs, got {} literals",
        literals.len(),
    );

    let anchors: Vec<String> = literals.into_iter().step_by(2).collect();
    for anchor in &anchors {
        assert!(
            is_anchor_shaped(anchor),
            "parsed {anchor:?} as an ANCHORS name, which is not a dotted lowercase path; the \
             pair parse has slipped out of step",
        );
    }
    anchors
}

/// Removes `/* */` block comments, including nested ones.
///
/// `strip_line_comments` handles `//` only, so without this a deleted call site
/// commented out as `/* failpoint!("x") */` stays in the scanned set and the
/// scan passes over source that no longer exists. `lore-postgres/src` has no
/// block comment today; this closes the class rather than a live defect.
fn strip_block_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut index = 0;
    let mut depth = 0usize;
    while index + 1 < bytes.len() {
        if bytes[index] == b'/' && bytes[index + 1] == b'*' {
            depth += 1;
            out[index] = b' ';
            out[index + 1] = b' ';
            index += 2;
        } else if depth > 0 && bytes[index] == b'*' && bytes[index + 1] == b'/' {
            depth -= 1;
            out[index] = b' ';
            out[index + 1] = b' ';
            index += 2;
        } else {
            // Blank the body but keep newlines, so line-based reasoning about
            // the result stays meaningful.
            if depth > 0 && bytes[index] != b'\n' {
                out[index] = b' ';
            }
            index += 1;
        }
    }
    match String::from_utf8(out) {
        Ok(masked) => masked,
        Err(error) => panic!("block-comment masking must stay valid UTF-8: {error}"),
    }
}

/// Every `.rs` file under `lore-postgres/src`, recursively.
///
/// `mod.rs` re-exports the macro with `pub(crate) use failpoint;`, so
/// `failpoint!` is callable from anywhere in the crate. Scanning one file would
/// let an undeclared anchor in any other file pass.
fn crate_source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) => panic!("{} must be readable: {error}", dir.display()),
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    walk(&root, &mut found);
    found.sort();
    assert!(
        !found.is_empty(),
        "no source files found under {}; the scan is broken, not the code",
        root.display(),
    );
    found
}

/// Anchor names passed to `failpoint!` anywhere in `lore-postgres/src`.
///
/// Reads the anchor rather than matching the literal bytes `failpoint!("`,
/// because rustfmt wraps a long invocation as `failpoint!(\n    "anchor"\n)?;`
/// and the byte match would silently skip it — the fork's own mandatory
/// formatter manufacturing a blind spot in the scan. Anything that looks like an
/// invocation but whose anchor cannot be read is a hard failure, never a skip.
fn called_anchors() -> Vec<String> {
    let mut found = Vec::new();
    for path in crate_source_files() {
        let raw = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => panic!("{} must be readable: {error}", path.display()),
        };
        // Both strippers are load-bearing, and over-stripping is safe.
        //
        // Load-bearing: a doc comment is exactly where someone writes an example
        // invocation, and widening this scan to the whole crate walks it into
        // the files where those live -- `mod.rs`'s own usage example and
        // `failpoints.rs`'s note about it both write `failpoint!("anchor.name")`
        // in prose, and neither is a declared anchor. Revert-checked: dropping
        // `strip_line_comments` here fails this test with `"anchor.name"` in the
        // called set.
        //
        // Safe: stripping only ever removes text, so the worst case is a *missed*
        // call site -- and a missed call site is caught anyway, because its
        // anchor then has no caller and the set-equality assertion fails from the
        // declared-but-not-called side. That is a property of asserting equality
        // in both directions rather than just "every call site is declared", and
        // it is why an over-eager stripper here cannot hide a real call site.
        let source = strip_block_comments(&strip_line_comments(&raw));
        let file = path.display();
        for (offset, _) in source.match_indices("failpoint!") {
            let rest = source[offset + "failpoint!".len()..].trim_start();
            let Some(after_delimiter) = rest.strip_prefix('(') else {
                // A macro can also be invoked as `failpoint!{..}` or
                // `failpoint![..]`; neither is used here and both would evade
                // an anchor read, so they are refused rather than skipped.
                assert!(
                    !rest.starts_with('{') && !rest.starts_with('['),
                    "{file} invokes failpoint! with a non-parenthesised delimiter, which this \
                     scan cannot read; use failpoint!(\"anchor\")",
                );
                // Otherwise this is prose inside a string literal that mentions
                // the macro by name (`failpoints.rs`'s own test messages do).
                continue;
            };
            let anchor_start = after_delimiter.trim_start();
            if anchor_start.starts_with('\\') {
                // `failpoint!(\"` only occurs inside a Rust string literal that
                // quotes the scan token itself — `failpoints.rs`'s own scanner.
                // A genuine invocation cannot contain an escaped quote here.
                continue;
            }
            let Some(literal) = anchor_start.strip_prefix('"') else {
                panic!(
                    "{file} invokes failpoint! with a non-literal anchor; this scan can only \
                     verify a string literal",
                );
            };
            match literal.find('"') {
                Some(end) => found.push(literal[..end].to_string()),
                None => panic!("{file} has an unterminated failpoint! anchor"),
            }
        }
    }
    found
}

/// Every `failpoint!` anchor is declared, and every declared anchor is called.
///
/// This is the same property as `failpoints.rs`'s own
/// `the_anchor_table_and_the_call_sites_name_the_same_set`, deliberately
/// duplicated in the default tier because that one compiles only under
/// `--features failure_generator`, which no CI job runs tests with. See the
/// module docs for why a mistyped anchor otherwise reaches no gate at all.
#[test]
fn every_failpoint_anchor_is_declared_even_in_a_default_build() {
    let mut called = called_anchors();
    assert!(
        !called.is_empty(),
        "no failpoint! call sites found; the scan is broken, not the code",
    );
    called.sort();
    called.dedup();

    let mut declared = declared_anchors();
    declared.sort();
    declared.dedup();

    assert_eq!(
        called, declared,
        "every failpoint! anchor anywhere in lore-postgres/src must be declared in ANCHORS, and \
         every declared anchor must have a call site; an undeclared anchor is dropped by the \
         configuration parser and its call site is silently unreachable",
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
