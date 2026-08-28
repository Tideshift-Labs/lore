// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Character-class coverage for the canonical-ID validation that CR-033's contract-move refactor
//! relocates from `auth::validate_id` to `contract::validate_canonical_id`.
//!
//! `contract` is crate-private, so this suite drives the moved logic exclusively through its
//! public caller: `SpoolLayout::derive_boundary_binding` (`spool.rs`), which maps the same
//! acceptance/rejection boundary to its own typed error (`SpoolLayoutError::InvalidBoundaryId`).
//! `auth.rs` and its `AuthorizedCallerRegistry` wrapper were the character-class matrix's other
//! caller before CR-033 removed the source-dark service shell (D1/D6/P2); `spool.rs` is now the
//! sole surviving public caller of the shared byte-class check.

use std::path::PathBuf;

use lore_object_dispatch::SpoolLayout;
use lore_object_dispatch::SpoolLayoutError;

fn spool_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\object-dispatch-spool-canonical-id-fixture")
    } else {
        PathBuf::from("/var/lib/object-dispatch-spool-canonical-id-fixture")
    }
}

fn spool_boundary_result(provider_boundary_id: &str) -> Result<(), SpoolLayoutError> {
    let layout =
        SpoolLayout::new(spool_root()).expect("absolute normalized test root must be valid");
    layout
        .derive_boundary_binding(provider_boundary_id)
        .map(|_| ())
}

// -- Character-class matrix, driven through the sole surviving spool.rs wrapper --------------

#[test]
fn empty_id_is_rejected() {
    assert_eq!(
        spool_boundary_result(""),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
}

#[test]
fn id_at_exactly_256_bytes_is_accepted() {
    let id = "a".repeat(256);
    assert_eq!(id.len(), 256);
    assert!(spool_boundary_result(&id).is_ok());
}

#[test]
fn id_at_257_bytes_is_rejected() {
    let id = "a".repeat(257);
    assert_eq!(id.len(), 257);
    assert_eq!(
        spool_boundary_result(&id),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
}

#[test]
fn leading_byte_must_be_ascii_alphanumeric() {
    for leading in ['.', '_', ':', '/', '-'] {
        let id = format!("{leading}rest-of-id");
        assert_eq!(
            spool_boundary_result(&id),
            Err(SpoolLayoutError::InvalidBoundaryId),
            "leading {leading:?} must be rejected"
        );
    }
}

#[test]
fn embedded_space_is_rejected() {
    assert_eq!(
        spool_boundary_result("valid id"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
}

#[test]
fn embedded_nul_is_rejected() {
    assert_eq!(
        spool_boundary_result("valid\0id"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
}

#[test]
fn non_ascii_multibyte_utf8_is_rejected() {
    // "valid\u{00e9}id" contains an accented e (U+00E9), which encodes as two UTF-8 bytes, neither
    // of which is ASCII alphanumeric or one of the five allowed punctuation bytes.
    assert_eq!(
        spool_boundary_result("valid\u{00e9}id"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
}

#[test]
fn ascii_control_byte_is_rejected() {
    let id = format!("valid{}id", '\u{0001}');
    assert_eq!(
        spool_boundary_result(&id),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
}

#[test]
fn ascii_punctuation_outside_the_allowed_five_is_rejected() {
    for byte in ['!', '@', '#', '$', '%', '+', ',', ';', '=', '\\'] {
        let id = format!("valid{byte}id");
        assert_eq!(
            spool_boundary_result(&id),
            Err(SpoolLayoutError::InvalidBoundaryId),
            "punctuation {byte:?} must be rejected"
        );
    }
}

#[test]
fn allowed_character_set_is_accepted() {
    // Every allowed punctuation byte (`.` `_` `:` `/` `-`) plus alphanumerics, first byte alphanumeric.
    assert!(spool_boundary_result("a0.b_c:d/e-F9").is_ok());
}
