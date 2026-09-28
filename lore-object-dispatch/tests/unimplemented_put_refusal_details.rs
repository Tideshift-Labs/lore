// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Tripwire for two proto messages nothing implements (WP-115 ledger row 22).
//!
//! `lore.object_dispatch.v1.PutUploadClosedV1` and `PutReservationUnavailableV1`
//! are the typed refusal details `object-store-budget-v1` describes for
//! `UPLOAD_CLOSED` and `DISPATCH_PUT_RESERVATION_UNAVAILABLE`. Both nest an
//! `ObjectStoreNoDispatchProofV1` that carries its own `logical_request_id`, and
//! that nested identity must equal the parent's `logical_request_id` before the
//! proof means anything. WP-115 cut both typed details (KV, 2026-09-27): the
//! in-process authority refuses with a closed error instead, and no code
//! builds, encodes, decodes, or reads either message.
//!
//! This test fails the moment production source names either message, or the
//! detail's digest domain. It is not a ban on the feature. It is a demand that
//! whoever implements it first also writes the nested request-identity check
//! and a test that pins it, and then replaces this tripwire with a test of that
//! check.
//!
//! # Why a source scan and not a type-level guard
//!
//! A type-level guard would need the generated structs to be unconstructible
//! without the check. They are prost messages with public fields and a
//! `Default` impl, generated from the proto, and this fork never patches
//! generated Rust. A wrapper type proves nothing while the raw struct stays one
//! literal away. So the least brittle guard is a scan of every workspace crate's
//! `src/` for the two identifiers, which is what an implementation cannot avoid
//! writing.
//!
//! The scan errs toward failing. Comments are stripped conservatively (a line
//! holding a `"` is kept whole), so a mention can only be missed if it sits in
//! a comment, and a block comment is scanned as code. `#[cfg(test)]` modules in
//! `src/` are scanned too. The only exclusion is the generated binding file,
//! which declares the messages. Integration tests under `tests/` are not
//! production code and are not scanned.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// What an implementation of either typed detail cannot avoid naming.
const UNIMPLEMENTED: [&str; 3] = [
    "PutUploadClosedV1",
    "PutReservationUnavailableV1",
    // The contract's digest domain for the reservation-unavailable detail.
    "object-store-put-reservation-unavailable-v1",
];

/// The generated file that declares both messages. Excluded by exact path.
const GENERATED_BINDINGS: &str = "lore-proto/src/grpc/lore.object_dispatch.v1.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lore-object-dispatch sits inside the workspace root")
        .to_path_buf()
}

fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Every `src/**/*.rs` of every crate directly under the workspace root, except
/// the generated bindings. `target/` and `vendor/` hold no `src/` of ours at
/// depth one, and `vendor/` is patched upstream code.
fn production_sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut files = Vec::new();
    for entry in fs::read_dir(&root).expect("workspace root is readable") {
        let crate_dir = entry.expect("workspace entry").path();
        let name = crate_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if name == "target" || name == "vendor" || name.starts_with('.') {
            continue;
        }
        let src = crate_dir.join("src");
        if crate_dir.join("Cargo.toml").is_file() && src.is_dir() {
            rust_files_under(&src, &mut files);
        }
    }
    files
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            if relative == GENERATED_BINDINGS {
                return None;
            }
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"));
            Some((relative, text))
        })
        .collect()
}

/// Removes `//` comments conservatively: a line holding a `"` is kept whole, so
/// a string literal can never hide real code behind a cut.
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

/// Whether `token` occurs in `code` as a whole identifier, so the scan does not
/// trip on the sibling enum `PutUploadClosedStateV1`.
fn names(code: &str, token: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    code.match_indices(token).any(|(start, _)| {
        let before = code[..start].chars().next_back();
        let after = code[start + token.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

#[test]
fn no_production_code_builds_an_unimplemented_put_refusal_detail() {
    let sources = production_sources();
    let mut offenders = Vec::new();
    for (path, text) in &sources {
        let code = strip_line_comments(text);
        for token in UNIMPLEMENTED {
            if names(&code, token) {
                offenders.push(format!("{path}: {token}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "production code now names an unimplemented typed refusal detail:\n  {}\n\n\
         WP-115 ledger row 22 cut PutUploadClosedV1 and PutReservationUnavailableV1. Each nests \
         an ObjectStoreNoDispatchProofV1 whose logical_request_id must equal the parent's \
         logical_request_id. Before building or reading either message, write that check and a \
         test that pins it (see reserve_put.rs, validate_no_dispatch_proof), then replace this \
         tripwire with a test of the check.",
        offenders.join("\n  ")
    );
}

/// The scan must have read the workspace, including the one file whose comment
/// names both messages. A scan that silently read nothing would pass above.
#[test]
fn the_scan_reads_the_workspace_and_strips_the_documented_mention() {
    let sources = production_sources();
    assert!(
        sources.len() > 200,
        "expected the whole workspace's src/, read {} files",
        sources.len()
    );
    assert!(
        !sources.iter().any(|(path, _)| path == GENERATED_BINDINGS),
        "the generated bindings must be the one exclusion"
    );
    let (_, reserve_put) = sources
        .iter()
        .find(|(path, _)| path == "lore-object-dispatch/src/reserve_put.rs")
        .expect("reserve_put.rs is scanned");
    assert!(
        names(reserve_put, "PutUploadClosedV1"),
        "reserve_put.rs documents both messages in a comment; if that prose went away this \
         check has stopped proving the stripper runs"
    );
    assert!(!names(
        &strip_line_comments(reserve_put),
        "PutUploadClosedV1"
    ));

    // The generated file really declares them, so the tokens are spelled right.
    let generated =
        fs::read_to_string(workspace_root().join(GENERATED_BINDINGS)).expect("generated bindings");
    for token in &UNIMPLEMENTED[..2] {
        assert!(names(&generated, token), "{token} must be declared");
    }
}

/// The matcher and stripper, on inputs that pin the directions that matter.
#[test]
fn the_matcher_finds_code_and_ignores_siblings_and_comments() {
    assert!(names(
        "let d = PutUploadClosedV1::default();",
        "PutUploadClosedV1"
    ));
    assert!(names(
        "v1::PutReservationUnavailableV1 {",
        "PutReservationUnavailableV1"
    ));
    assert!(!names(
        "PutUploadClosedStateV1::UploadClosed",
        "PutUploadClosedV1"
    ));
    assert!(!names(
        &strip_line_comments("// PutUploadClosedV1\nlet x = 1; // PutUploadClosedV1"),
        "PutUploadClosedV1"
    ));
    // A string on the line keeps the whole line, so code cannot hide behind it.
    assert!(names(
        &strip_line_comments(r#"let s = "//"; let d = PutUploadClosedV1::default();"#),
        "PutUploadClosedV1"
    ));
    // A block comment is scanned as code: the safe direction.
    assert!(names(
        &strip_line_comments("/* PutUploadClosedV1 */"),
        "PutUploadClosedV1"
    ));
}
