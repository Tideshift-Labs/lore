// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 K10): which identity the repository connect authenticates as.
//!
//! A commit that asked for declared uploads may name its author with a given identity (the
//! desktop passes a display name). The connect looks its token up by identity, so it must use
//! the repository's own identity there, never the given author name.

use lore_revision::repository::connect_identity;

fn some(value: &str) -> Option<String> {
    Some(value.to_owned())
}

#[test]
fn a_managed_commit_with_a_given_identity_connects_as_the_repository_identity() {
    assert_eq!(
        connect_identity(true, true, &some("user-123"), &some("Display Name")),
        some("user-123"),
    );
}

#[test]
fn a_managed_commit_with_a_given_identity_and_no_repository_identity_connects_with_none() {
    assert_eq!(
        connect_identity(true, true, &None, &some("Display Name")),
        None,
    );
}

#[test]
fn a_managed_commit_without_a_given_identity_keeps_the_resolved_identity() {
    assert_eq!(
        connect_identity(true, false, &some("user-123"), &some("user-123")),
        some("user-123"),
    );
}

#[test]
fn a_stock_command_connects_as_its_given_identity() {
    assert_eq!(
        connect_identity(false, true, &some("user-123"), &some("Display Name")),
        some("Display Name"),
    );
}

/// The choice only matters if `load_and_connect` hands it to the connect. A source pin, because
/// no in-process cell runs auth on, so a live test cannot tell the two identities apart.
#[test]
fn load_and_connect_passes_the_chosen_identity_to_the_connect() {
    let source = include_str!("../../../src/repository.rs");
    assert!(
        source.contains("let remote = connect(repository, global, &config, connect_identity);"),
        "load_and_connect must connect with connect_identity, not the author identity"
    );
    assert!(
        source
            .contains("managed_commit_uploads_requested(),\n        global.identity().is_some(),"),
        "the choice must read the managed-commit request and whether an identity was given"
    );
}
