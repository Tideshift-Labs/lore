// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_base::types::KeyType;
use lore_postgres::domain::bypass;
use lore_server::domain::backfill_source::*;

/// The scan must cover exactly what `bypass::is_domain_owned` fences.
///
/// A type in the scan that is not fenced would make a legitimate row look
/// like residue; a fenced type missing from the scan hides a write the
/// cutover gate exists to refuse on.
#[test]
fn the_residue_scan_covers_exactly_what_the_bypass_guard_fences() {
    let types = domain_key_types();
    for key_type in (0u8..=u8::MAX).filter_map(|value| KeyType::try_from(value).ok()) {
        assert_eq!(
            types.contains(&(key_type as i16)),
            bypass::is_domain_owned(key_type),
            "{key_type:?} must be scanned exactly when the bypass guard fences it"
        );
    }
}

/// `Instance` is the only scanned type `classify_residue` maps to
/// `ForeignDomainKeyWrite`, and that class is the only one
/// `DomainBackfill::complete` refuses cutover on. Omitting it from the scan
/// left that refusal unreachable while every gate stayed green.
#[test]
fn the_scan_reaches_the_one_class_that_refuses_cutover() {
    let types = domain_key_types();
    assert!(
        types.contains(&(KeyType::Instance as i16)),
        "an Instance-typed row is reachable from a client through the seven generic \
         mutable RPCs and is what the cutover's foreign-write gate exists to catch"
    );
    for absent in [KeyType::Untyped, KeyType::Resolve] {
        assert!(
            !types.contains(&(absent as i16)),
            "{absent:?} is acceleration or resolution, not domain lifecycle; scanning it \
             would report ordinary rows as foreign writes and block every cutover"
        );
    }
}

#[test]
fn a_repository_identity_must_be_sixteen_bytes() {
    assert!(repository_identity(&[7u8; 16]).is_ok());
    for width in [0usize, 15, 17, 32] {
        let error = repository_identity(&vec![7u8; width])
            .expect_err("a non-16-byte identity must be refused");
        assert!(
            error.to_string().contains(&width.to_string()),
            "the refusal must name the observed width, got: {error}"
        );
    }
}

#[test]
fn a_sixteen_byte_identity_round_trips_its_bytes() {
    let bytes: [u8; 16] = std::array::from_fn(|index| index as u8);
    let id = repository_identity(&bytes).expect("16 bytes is a valid identity");
    assert_eq!(id.data(), &bytes);
}
