// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! CR-030: [`OwnershipToken`]'s three-way wire decode, and the redaction every type carrying one
//! promises. Independent of any [`AttemptStore`] implementation -- these are pure, offline
//! properties of the newtype itself.
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_transport::attempt_store::*;
use lore_transport::outcome::AttemptId;

fn token(fill: u8) -> OwnershipToken {
    OwnershipToken::from_wire(&[fill; OwnershipToken::LEN])
        .expect("32 bytes must decode without error")
        .expect("32 bytes must produce a token, not None")
}

/// An unfenced cell (or a legacy read path) returns an empty token, and that is not an
/// error -- it is the "no fenced authority here" answer.
#[test]
fn from_wire_empty_is_ok_none() {
    assert_eq!(
        OwnershipToken::from_wire(&[]).expect("empty must not error"),
        None
    );
}

/// The exact width CR-030 mints round-trips byte for byte.
#[test]
fn from_wire_exact_width_is_some_and_preserves_the_bytes() {
    let bytes = [0x42u8; OwnershipToken::LEN];
    let decoded = OwnershipToken::from_wire(&bytes)
        .expect("exact width must not error")
        .expect("exact width must produce a token");
    assert_eq!(decoded.as_bytes().as_ref(), bytes.as_slice());
}

/// Any width other than 0 or exactly 32 is an error, never a silently dropped token -- a
/// token this client cannot hold onto is a lock it cannot release, and `Ok(None)` here would
/// make that failure indistinguishable from an ordinary unfenced acquire.
#[test]
fn from_wire_wrong_width_is_an_error_not_a_silently_dropped_token() {
    for bad_len in [1usize, OwnershipToken::LEN - 1, OwnershipToken::LEN + 1, 64] {
        let bytes = vec![0x11u8; bad_len];
        let error = OwnershipToken::from_wire(&bytes)
            .expect_err(&format!("width {bad_len} must be refused"));
        assert!(
            error.is_internal(),
            "a malformed token width must surface as an ordinary internal error, not a \
             retryable/disconnect-shaped one a caller might treat as safe to retry: {error:?}"
        );
    }
}

/// The whole reason for the newtype: formatting it never prints the bearer secret.
#[test]
fn debug_never_prints_the_token_bytes() {
    let formatted = format!("{:?}", token(0xAB));
    assert_eq!(formatted, "OwnershipToken(<redacted>)");
}

/// [`LockOwnership`]'s hand-written `Debug` must redact the token while leaving the other
/// fields legible -- the whole point of writing it by hand instead of deriving it.
#[test]
fn lock_ownership_debug_redacts_the_token_but_keeps_the_other_fields_readable() {
    let ownership = LockOwnership {
        attempt_id: AttemptId::new(),
        branch: Context::from([0x11u8; 16]),
        resource_hash: Hash::from([0x22u8; 32]),
        token: token(0xAB),
    };
    let formatted = format!("{ownership:?}");

    assert!(
        formatted.contains("OwnershipToken(<redacted>)"),
        "the token field must redact: {formatted}"
    );
    assert!(
        !formatted.contains("\\xab\\xab\\xab\\xab"),
        "the raw token bytes must never leak through the struct's own Debug: {formatted}"
    );
    assert!(
        formatted.contains("attempt_id") && formatted.contains("resource_hash"),
        "redacting the token must not swallow the struct's other fields: {formatted}"
    );
}
