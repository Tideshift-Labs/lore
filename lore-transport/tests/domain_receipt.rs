// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// CR-029/WP-120 domain-receipt client-side type fixtures.
//
// [CLIENT]-class: `lore-transport` is a client-path crate. Pure, offline fixtures, no live
// server -- an external test target (not an inline `#[cfg(test)] mod`), matching
// `outcome_contract.rs`'s own convention, so this file exercises ONLY the crate's PUBLIC surface
// re-exported from the crate root, not `domain_receipt`'s internals directly.
//
// This file pins `DomainReceiptQuery::validate()` and the plain `DomainReceiptState`/
// `DomainReceiptOutcome` type shapes -- the parts of `domain_receipt.rs` that are pure and fully
// testable without a live server. The RPC-calling half (the actual `DomainOperationReceiptGet`
// client, its auth-interceptor wiring, and its `tonic::Status` -> `DomainReceipt` decoding) has
// landed in `grpc/domain_operation_client.rs`, which owns its own in-process-tonic-server
// `live_tests` suite; this file does not duplicate that coverage.

use bytes::Bytes;
use lore_transport::DomainReceipt;
use lore_transport::DomainReceiptOutcome;
use lore_transport::DomainReceiptQuery;
use lore_transport::DomainReceiptState;
use lore_transport::RECEIPT_DIGEST_LEN;
use uuid::Uuid;

fn digest(fill: u8) -> Bytes {
    Bytes::from(vec![fill; RECEIPT_DIGEST_LEN])
}

/// A structurally valid query. Every individual-field test below clones this and disturbs
/// exactly one field, so a failure localizes to the field the test claims to cover.
fn valid_query() -> DomainReceiptQuery {
    DomainReceiptQuery {
        org_uuid: Uuid::now_v7(),
        initiating_principal_namespace: Bytes::from_static(b"human-principal-namespace"),
        operation_id: Uuid::now_v7(),
        method: "RevisionService.BranchPush".to_string(),
        scope: Bytes::from_static(b"repository-scope"),
        fingerprint_version: 1,
        fingerprint: digest(0xAA),
        canonical_intent_digest: digest(0xBB),
        authorization_revision: 1,
        consumed_ticket_sha256: digest(0xCC),
    }
}

/// Reachability: every symbol a downstream caller needs, addressed through nothing but the
/// crate root. If any of these were only `pub` inside `domain_receipt.rs` without a crate-root
/// re-export, this file would fail to compile -- that is the proof, not any runtime assertion.
#[test]
fn the_public_domain_receipt_surface_is_reachable_through_the_crate_root() {
    let query = valid_query();
    assert_eq!(query.validate(), Ok(()));

    let receipt = DomainReceipt {
        state: DomainReceiptState::Committed {
            outcome: DomainReceiptOutcome::Applied,
            from_future_marker: false,
        },
        verification_nonce: digest(1),
        bound_fields_digest: digest(2),
        consumed_ticket_sha256: digest(3),
        authorization_revision: 1,
    };
    assert!(receipt.state.is_attributive());
}

#[test]
fn a_structurally_complete_query_validates() {
    assert_eq!(valid_query().validate(), Ok(()));
}

#[test]
fn an_empty_initiating_principal_namespace_is_rejected() {
    let mut query = valid_query();
    query.initiating_principal_namespace = Bytes::new();
    assert_eq!(
        query.validate(),
        Err("initiating_principal_namespace must not be empty")
    );
}

#[test]
fn an_empty_method_is_rejected() {
    let mut query = valid_query();
    query.method = String::new();
    assert_eq!(query.validate(), Err("method must not be empty"));
}

#[test]
fn an_empty_scope_is_rejected() {
    let mut query = valid_query();
    query.scope = Bytes::new();
    assert_eq!(query.validate(), Err("scope must not be empty"));
}

#[test]
fn a_zero_fingerprint_version_is_rejected() {
    let mut query = valid_query();
    query.fingerprint_version = 0;
    assert_eq!(query.validate(), Err("fingerprint_version must be nonzero"));
}

#[test]
fn a_zero_authorization_revision_is_rejected() {
    let mut query = valid_query();
    query.authorization_revision = 0;
    assert_eq!(
        query.validate(),
        Err("authorization_revision must be nonzero")
    );
}

/// Exact-byte-length pins for all three digest fields: the accepted boundary
/// (`RECEIPT_DIGEST_LEN`) and one byte under and over it, matching the fork's convention of
/// pinning both sides of a byte-boundary check rather than only the rejection.
#[test]
fn fingerprint_must_be_exactly_the_digest_length() {
    let mut short = valid_query();
    short.fingerprint = Bytes::from(vec![0xAA; RECEIPT_DIGEST_LEN - 1]);
    assert_eq!(
        short.validate(),
        Err("fingerprint must be exactly 32 bytes")
    );

    let mut long = valid_query();
    long.fingerprint = Bytes::from(vec![0xAA; RECEIPT_DIGEST_LEN + 1]);
    assert_eq!(long.validate(), Err("fingerprint must be exactly 32 bytes"));

    let mut exact = valid_query();
    exact.fingerprint = Bytes::from(vec![0xAA; RECEIPT_DIGEST_LEN]);
    assert_eq!(exact.validate(), Ok(()));
}

#[test]
fn canonical_intent_digest_must_be_exactly_the_digest_length() {
    let mut short = valid_query();
    short.canonical_intent_digest = Bytes::from(vec![0xBB; RECEIPT_DIGEST_LEN - 1]);
    assert_eq!(
        short.validate(),
        Err("canonical_intent_digest must be exactly 32 bytes")
    );

    let mut long = valid_query();
    long.canonical_intent_digest = Bytes::from(vec![0xBB; RECEIPT_DIGEST_LEN + 1]);
    assert_eq!(
        long.validate(),
        Err("canonical_intent_digest must be exactly 32 bytes")
    );

    let mut exact = valid_query();
    exact.canonical_intent_digest = Bytes::from(vec![0xBB; RECEIPT_DIGEST_LEN]);
    assert_eq!(exact.validate(), Ok(()));
}

#[test]
fn consumed_ticket_sha256_must_be_exactly_the_digest_length() {
    let mut short = valid_query();
    short.consumed_ticket_sha256 = Bytes::from(vec![0xCC; RECEIPT_DIGEST_LEN - 1]);
    assert_eq!(
        short.validate(),
        Err("consumed_ticket_sha256 must be exactly 32 bytes")
    );

    let mut long = valid_query();
    long.consumed_ticket_sha256 = Bytes::from(vec![0xCC; RECEIPT_DIGEST_LEN + 1]);
    assert_eq!(
        long.validate(),
        Err("consumed_ticket_sha256 must be exactly 32 bytes")
    );

    let mut exact = valid_query();
    exact.consumed_ticket_sha256 = Bytes::from(vec![0xCC; RECEIPT_DIGEST_LEN]);
    assert_eq!(exact.validate(), Ok(()));
}

/// `operation_id` is reused for the lookup and must be the same UUIDv7 the attempt was minted
/// with -- a v4 (or any non-v7) id can never have been a real attempt id, so `validate()` rejects
/// it before a round trip can discover the same thing the hard way.
#[test]
fn a_non_v7_operation_id_is_rejected() {
    let mut query = valid_query();
    query.operation_id = Uuid::new_v4();
    assert_eq!(query.validate(), Err("operation_id must be a UUIDv7"));
}

#[test]
fn a_v7_operation_id_is_accepted() {
    let mut query = valid_query();
    query.operation_id = Uuid::now_v7();
    assert_eq!(query.validate(), Ok(()));
}

/// `validate()`'s own doc comment states this is deliberate: the server owns its upper bounds on
/// `method`, `scope`, and `initiating_principal_namespace`, and the client does not duplicate
/// them. Pinned as a positive case, not just an absence of a check, so a future change that adds
/// a client-side upper bound here changes this test rather than silently diverging from a bound
/// the server might later change. An implementation that *did* duplicate the server's bound would
/// fail this with `InvalidArgument`-shaped rejection; the server is the one that answers that.
#[test]
fn validate_does_not_duplicate_the_servers_upper_bounds() {
    let mut long_method = valid_query();
    long_method.method = "x".repeat(10_000);
    assert_eq!(long_method.validate(), Ok(()));

    let mut long_scope = valid_query();
    long_scope.scope = Bytes::from(vec![b'x'; 10_000]);
    assert_eq!(long_scope.validate(), Ok(()));

    let mut long_namespace = valid_query();
    long_namespace.initiating_principal_namespace = Bytes::from(vec![b'x'; 10_000]);
    assert_eq!(long_namespace.validate(), Ok(()));
}

/// The single predicate a reconciler branches on: only `Committed` attributes an outcome to the
/// exact attempt. Every other variant -- including `NotFound`, which represents plain absence --
/// must read as non-attributive, never as an error the caller has to unwrap or match separately.
/// This is `absent maps to absent, not error` at the type level: `NotFound` is a normal,
/// non-panicking variant of the same enum as `Committed`, not a `Result::Err`.
#[test]
fn only_committed_is_attributive() {
    let committed = DomainReceiptState::Committed {
        outcome: DomainReceiptOutcome::Applied,
        from_future_marker: false,
    };
    assert!(committed.is_attributive());

    let non_attributive = [
        DomainReceiptState::Prepared {
            prepared_at_unix_millis: 0,
            hard_expires_at_unix_millis: 0,
        },
        DomainReceiptState::Mismatch,
        DomainReceiptState::Expired,
        DomainReceiptState::ExpiredOrUnknown,
        DomainReceiptState::NotFound,
    ];
    for state in non_attributive {
        assert!(
            !state.is_attributive(),
            "{state:?} must not be attributive -- only Committed carries a decisive outcome"
        );
    }
}

/// `Committed` with a `NotApplied` outcome is still attributive: the server ran and recorded
/// that the effect did not happen for *this* attempt, which is exactly the decisive information
/// a reconciler needs, distinct from every non-attributive "we don't know" state above.
#[test]
fn a_committed_not_applied_outcome_is_still_attributive() {
    let state = DomainReceiptState::Committed {
        outcome: DomainReceiptOutcome::NotApplied {
            reason_version: 1,
            reason: "PREPARED_HARD_TTL_EXPIRED_V1".to_string(),
        },
        from_future_marker: false,
    };
    assert!(state.is_attributive());
}
