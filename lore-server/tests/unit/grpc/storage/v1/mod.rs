// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

mod copy;
mod get_resolved;
mod mutable_load;
mod mutable_store;
mod put_resolved;
mod query;
mod service;
mod test_utils;

use lore_server::grpc::storage::v1::STREAM_PROCESS_LIMIT;
use lore_server::grpc::storage::v1::parse_put_concurrency;

#[test]
fn parses_a_positive_override() {
    assert_eq!(parse_put_concurrency(Some("32".to_string())), 32);
}

#[test]
fn absent_falls_back_to_default() {
    assert_eq!(parse_put_concurrency(None), STREAM_PROCESS_LIMIT);
}

#[test]
fn invalid_present_values_fall_back_to_default() {
    // zero, negative, non-numeric, and empty all revert to the default.
    assert_eq!(
        parse_put_concurrency(Some("0".to_string())),
        STREAM_PROCESS_LIMIT
    );
    assert_eq!(
        parse_put_concurrency(Some("-4".to_string())),
        STREAM_PROCESS_LIMIT
    );
    assert_eq!(
        parse_put_concurrency(Some("nope".to_string())),
        STREAM_PROCESS_LIMIT
    );
    assert_eq!(
        parse_put_concurrency(Some(String::new())),
        STREAM_PROCESS_LIMIT
    );
}
