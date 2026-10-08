// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
mod discovery;

use lore_transport::auth::oidc::*;

/// A body longer than the log excerpt is cut, and says so.
#[test]
fn a_long_body_is_excerpted_for_the_log() {
    let short = "not a document";
    assert_eq!(body_excerpt(short), short);

    let long = "x".repeat(LOGGED_BODY_LIMIT * 3);
    let excerpt = body_excerpt(&long);
    assert!(excerpt.len() < long.len());
    assert!(excerpt.contains(&format!("({} bytes total)", long.len())));
}

/// Multi-byte characters must not be split when excerpting, or the log line panics.
#[test]
fn excerpting_respects_character_boundaries() {
    let body = "é".repeat(LOGGED_BODY_LIMIT * 2);
    let excerpt = body_excerpt(&body);
    assert!(excerpt.contains('é'));
}
