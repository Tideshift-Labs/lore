// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Character-class coverage for the canonical-ID validation that CR-033's contract-move refactor
//! relocates from `auth::validate_id` to `contract::validate_canonical_id`.
//!
//! `contract` is crate-private, so this suite drives the moved logic exclusively through its two
//! public callers: `AuthorizedCallerRegistry::new` (`auth.rs`) and `SpoolLayout::derive_boundary_binding`
//! (`spool.rs`). Both wrappers must keep mapping the same acceptance/rejection boundary to their own
//! typed error (`CallerRegistryError::InvalidId` / `SpoolLayoutError::InvalidBoundaryId`) regardless of
//! which module owns the underlying byte-class check.

use std::path::PathBuf;

use lore_object_dispatch::AuthorizedCallerEntry;
use lore_object_dispatch::AuthorizedCallerRegistry;
use lore_object_dispatch::CallerRegistryError;
use lore_object_dispatch::SpoolLayout;
use lore_object_dispatch::SpoolLayoutError;

const VALID_URI_SAN: &str = "spiffe://lorehub/object-dispatch/canonical-id-fixture";

fn entry_with_service_instance_id(service_instance_id: &str) -> AuthorizedCallerEntry {
    AuthorizedCallerEntry {
        uri_san: VALID_URI_SAN.to_string(),
        service_instance_id: service_instance_id.to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        allowed_cell_ids: vec!["cell-1".to_string()],
    }
}

fn registry_result(service_instance_id: &str) -> Result<(), CallerRegistryError> {
    AuthorizedCallerRegistry::new(vec![entry_with_service_instance_id(service_instance_id)])
        .map(|_| ())
}

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

// -- Character-class matrix, driven through the registry wrapper -----------------------------

#[test]
fn empty_id_is_rejected() {
    assert_eq!(registry_result(""), Err(CallerRegistryError::InvalidId));
}

#[test]
fn id_at_exactly_256_bytes_is_accepted() {
    let id = "a".repeat(256);
    assert_eq!(id.len(), 256);
    assert!(registry_result(&id).is_ok());
}

#[test]
fn id_at_257_bytes_is_rejected() {
    let id = "a".repeat(257);
    assert_eq!(id.len(), 257);
    assert_eq!(registry_result(&id), Err(CallerRegistryError::InvalidId));
}

#[test]
fn leading_byte_must_be_ascii_alphanumeric() {
    for leading in ['.', '_', ':', '/', '-'] {
        let id = format!("{leading}rest-of-id");
        assert_eq!(
            registry_result(&id),
            Err(CallerRegistryError::InvalidId),
            "leading {leading:?} must be rejected"
        );
    }
}

#[test]
fn embedded_space_is_rejected() {
    assert_eq!(
        registry_result("valid id"),
        Err(CallerRegistryError::InvalidId)
    );
}

#[test]
fn embedded_nul_is_rejected() {
    assert_eq!(
        registry_result("valid\0id"),
        Err(CallerRegistryError::InvalidId)
    );
}

#[test]
fn non_ascii_multibyte_utf8_is_rejected() {
    // "valid\u{00e9}id" contains an accented e (U+00E9), which encodes as two UTF-8 bytes, neither
    // of which is ASCII alphanumeric or one of the five allowed punctuation bytes.
    assert_eq!(
        registry_result("valid\u{00e9}id"),
        Err(CallerRegistryError::InvalidId)
    );
}

#[test]
fn ascii_control_byte_is_rejected() {
    let id = format!("valid{}id", '\u{0001}');
    assert_eq!(registry_result(&id), Err(CallerRegistryError::InvalidId));
}

#[test]
fn ascii_punctuation_outside_the_allowed_five_is_rejected() {
    for byte in ['!', '@', '#', '$', '%', '+', ',', ';', '=', '\\'] {
        let id = format!("valid{byte}id");
        assert_eq!(
            registry_result(&id),
            Err(CallerRegistryError::InvalidId),
            "punctuation {byte:?} must be rejected"
        );
    }
}

#[test]
fn allowed_character_set_is_accepted() {
    // Every allowed punctuation byte (`.` `_` `:` `/` `-`) plus alphanumerics, first byte alphanumeric.
    assert!(registry_result("a0.b_c:d/e-F9").is_ok());
}

// -- auth.rs wrapper: CallerRegistryError::InvalidId ------------------------------------------

#[test]
fn auth_wrapper_surfaces_invalid_id_for_service_instance_provider_boundary_and_allowed_cell() {
    assert_eq!(
        AuthorizedCallerRegistry::new(vec![entry_with_service_instance_id("")]).err(),
        Some(CallerRegistryError::InvalidId)
    );

    let mut bad_provider_boundary = entry_with_service_instance_id("service-1");
    bad_provider_boundary.provider_boundary_id = String::new();
    assert_eq!(
        AuthorizedCallerRegistry::new(vec![bad_provider_boundary]).err(),
        Some(CallerRegistryError::InvalidId)
    );

    let mut bad_cell = entry_with_service_instance_id("service-1");
    bad_cell.allowed_cell_ids = vec!["bad cell".to_string()];
    assert_eq!(
        AuthorizedCallerRegistry::new(vec![bad_cell]).err(),
        Some(CallerRegistryError::InvalidId)
    );

    // Positive control: an all-valid entry must still succeed through the same wrapper.
    assert!(registry_result("service-instance.1_ok:v1/a-b").is_ok());
}

// -- spool.rs wrapper: SpoolLayoutError::InvalidBoundaryId ------------------------------------

#[test]
fn spool_boundary_wrapper_surfaces_invalid_boundary_id() {
    assert_eq!(
        spool_boundary_result(""),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        spool_boundary_result(".leading-dot-boundary"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        spool_boundary_result("bad boundary id"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        spool_boundary_result(&"a".repeat(257)),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );

    // Positive control: an all-valid boundary ID (and the exact 256-byte boundary) must still
    // succeed through the same wrapper.
    assert!(spool_boundary_result("boundary.1_ok:v1/a-b").is_ok());
    assert!(spool_boundary_result(&"a".repeat(256)).is_ok());
}
