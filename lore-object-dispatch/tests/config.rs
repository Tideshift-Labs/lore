// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::CELL_AUTHORITY_CONFIG_REVISION;
use lore_object_dispatch::CELL_AUTHORITY_CONFIG_REVISION_ENV;
use lore_object_dispatch::CellAuthorityConfig;
use lore_object_dispatch::CellAuthorityConfigError;

fn revision_vars() -> Vec<(String, String)> {
    vec![(
        CELL_AUTHORITY_CONFIG_REVISION_ENV.to_string(),
        CELL_AUTHORITY_CONFIG_REVISION.to_string(),
    )]
}

#[test]
fn config_round_trips_the_exact_revision() {
    let config = CellAuthorityConfig::from_prefixed_vars(revision_vars())
        .expect("exact cell authority configuration must parse");

    assert_eq!(config.config_revision(), CELL_AUTHORITY_CONFIG_REVISION);
}

#[test]
fn config_has_no_implicit_default_revision() {
    assert_eq!(
        CellAuthorityConfig::from_prefixed_vars(std::iter::empty::<(&str, &str)>()),
        Err(CellAuthorityConfigError::MissingRevision)
    );
}

#[test]
fn config_rejects_changed_revision() {
    let vars = vec![(
        CELL_AUTHORITY_CONFIG_REVISION_ENV.to_string(),
        "object-store-cell-dispatch-authority-v2".to_string(),
    )];

    assert_eq!(
        CellAuthorityConfig::from_prefixed_vars(vars),
        Err(CellAuthorityConfigError::RevisionMismatch)
    );
}

#[test]
fn config_rejects_unknown_object_dispatch_keys() {
    let mut vars = revision_vars();
    vars.push((
        "LORE_OBJECT_DISPATCH_CONTINUITY_DATABASE_URL".to_string(),
        "postgresql://must-not-be-consumed".to_string(),
    ));

    assert_eq!(
        CellAuthorityConfig::from_prefixed_vars(vars),
        Err(CellAuthorityConfigError::UnknownVariable)
    );
}

#[test]
fn config_rejects_duplicate_revision_keys() {
    let mut vars = revision_vars();
    vars.push((
        CELL_AUTHORITY_CONFIG_REVISION_ENV.to_string(),
        CELL_AUTHORITY_CONFIG_REVISION.to_string(),
    ));

    assert_eq!(
        CellAuthorityConfig::from_prefixed_vars(vars),
        Err(CellAuthorityConfigError::DuplicateVariable)
    );
}

#[test]
fn config_ignores_unrelated_environment_keys() {
    let mut vars = revision_vars();
    vars.push((
        "UNRELATED_SECRET".to_string(),
        "must-not-be-read".to_string(),
    ));

    assert!(CellAuthorityConfig::from_prefixed_vars(vars).is_ok());
}

// -- The load-bearing case: a prefixed but non-Unicode variable name must fail closed rather
// -- than silently escaping the allowlist through a lossy string comparison. The prefix test in
// -- `config.rs` is deliberately bytewise and runs before Unicode conversion, so this must be
// -- exercised on both encodings this crate builds for.

#[cfg(unix)]
#[test]
fn config_rejects_bytewise_prefixed_nonunicode_key() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut key = b"LORE_OBJECT_DISPATCH_".to_vec();
    key.push(0xff);

    assert_eq!(
        CellAuthorityConfig::from_prefixed_vars([(
            OsString::from_vec(key),
            OsString::from("value")
        )]),
        Err(CellAuthorityConfigError::NonUnicodeKey)
    );
}

#[cfg(windows)]
#[test]
fn config_rejects_bytewise_prefixed_nonunicode_key() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // "LORE_OBJECT_DISPATCH_" followed by an unpaired UTF-16 high surrogate: ill-formed UTF-16,
    // so `OsString::into_string` fails, but the bytewise prefix check (which walks UTF-16 code
    // units, not `char`s) must still recognize the prefix and route this to `NonUnicodeKey`
    // rather than silently falling through `has_object_dispatch_prefix`'s `to_str` branch.
    let mut wide: Vec<u16> = "LORE_OBJECT_DISPATCH_".encode_utf16().collect();
    wide.push(0xD800);
    let key = OsString::from_wide(&wide);

    assert_eq!(
        CellAuthorityConfig::from_prefixed_vars([(key, OsString::from("value"))]),
        Err(CellAuthorityConfigError::NonUnicodeKey)
    );
}
