// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-120: the `lore-authn-bearer` metadata contract, exercised through the
//! only pieces of it `lore-server`'s public library surface exposes to an
//! external test -- `domain_operation_metadata::extract_authn_bearer` and its
//! companion refusal, `missing_authn_bearer`.
//!
//! `internal_admission_reason`/`admit_internal` (the code that actually wires
//! this extractor into a governed mutation's entry gate) are crate-private,
//! and their test-support fixtures (`DomainContext::test_support::context`,
//! `DirectVerifierDouble`) are `pub(crate)` -- deliberately not part of this
//! crate's external surface. That wiring, the ordering-property regression
//! (an earlier gate must keep its own outcome regardless of this header), and
//! the divergent-bearer-forwarding proof all live in `domain.rs`'s own
//! `#[cfg(test)] mod tests`, which can reach them directly. This file is
//! deliberately narrower: it pins the extractor's own contract in isolation,
//! independent of any caller.
//!
//! [SERVER]-side (`lore-server`): we control the deployed build.

use lore_server::grpc::domain_operation_metadata::AUTHN_BEARER_KEY;
use lore_server::grpc::domain_operation_metadata::MISSING_AUTHN_BEARER_MESSAGE;
use lore_server::grpc::domain_operation_metadata::extract_authn_bearer;
use lore_server::grpc::domain_operation_metadata::missing_authn_bearer;
use tonic::Code;
use tonic::metadata::MetadataMap;

#[test]
fn extract_authn_bearer_returns_the_value_verbatim_including_its_bearer_prefix() {
    let mut metadata = MetadataMap::new();
    metadata.insert(
        AUTHN_BEARER_KEY,
        "Bearer some.jwt.value".parse().expect("ascii header"),
    );

    let bearer = extract_authn_bearer(&metadata)
        .expect("a well-formed header must decode")
        .expect("a present header must not be reported absent");

    assert_eq!(
        bearer, "Bearer some.jwt.value",
        "the verifier is handed exactly what the client sent, prefix included"
    );
}

#[test]
fn extract_authn_bearer_reports_absence_when_the_header_is_not_present() {
    let metadata = MetadataMap::new();

    assert_eq!(
        extract_authn_bearer(&metadata).expect("absence is not an error"),
        None
    );
}

#[test]
fn extract_authn_bearer_treats_a_whitespace_only_value_as_absent() {
    let mut metadata = MetadataMap::new();
    metadata.insert(AUTHN_BEARER_KEY, "   ".parse().expect("ascii header"));

    assert_eq!(
        extract_authn_bearer(&metadata).expect("a blank header is not malformed"),
        None,
        "a blank header must never be forwarded as an empty credential"
    );
}

#[test]
fn extract_authn_bearer_refuses_divergent_duplicate_headers() {
    let mut metadata = MetadataMap::new();
    metadata.append(
        AUTHN_BEARER_KEY,
        "Bearer first".parse().expect("ascii header"),
    );
    metadata.append(
        AUTHN_BEARER_KEY,
        "Bearer second".parse().expect("ascii header"),
    );

    extract_authn_bearer(&metadata).expect_err("divergent duplicate values must be refused");
}

#[test]
fn extract_authn_bearer_accepts_identical_duplicate_headers() {
    let mut metadata = MetadataMap::new();
    metadata.append(
        AUTHN_BEARER_KEY,
        "Bearer same".parse().expect("ascii header"),
    );
    metadata.append(
        AUTHN_BEARER_KEY,
        "Bearer same".parse().expect("ascii header"),
    );

    assert_eq!(
        extract_authn_bearer(&metadata).expect("identical duplicates carry no ambiguity"),
        Some("Bearer same".to_owned())
    );
}

/// The server half of the pair `lore-transport`'s
/// `grpc::AUTHN_BEARER_METADATA_KEY` pins against. `lore-transport` cannot
/// depend on `lore-server`, so the two sides are kept equal by a literal plus
/// a source-location comment on each rather than a shared symbol -- see
/// `lore-transport/src/grpc/mod.rs`'s `AUTHN_BEARER_METADATA_KEY` doc comment
/// and `lore-transport/tests/authn_bearer_carriage.rs`'s literal-pin test.
#[test]
fn the_authn_bearer_metadata_key_is_the_literal_the_client_pins_against() {
    assert_eq!(AUTHN_BEARER_KEY, "lore-authn-bearer");
}

#[test]
fn missing_authn_bearer_is_failed_precondition_with_the_pinned_message() {
    let status = missing_authn_bearer();

    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_ne!(status.code(), Code::Unauthenticated);
    assert_ne!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), MISSING_AUTHN_BEARER_MESSAGE);
}
