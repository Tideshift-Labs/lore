// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_server::plugins::remote_notification::error::*;

#[test]
fn config_faults_translate_to_plugin_config_error() {
    let err = RemoteNotificationError::field("gateway_uri", "must use https");
    let plugin_error = err.into_plugin_error("remote");
    assert!(plugin_error.is_plugin_config_error());
}

#[test]
fn init_faults_translate_to_plugin_init_error() {
    let err = RemoteNotificationError::MtlsMaterialUnreadable {
        field: "client_key_path",
    };
    let plugin_error = err.into_plugin_error("remote");
    assert!(plugin_error.is_plugin_init_error());
}

#[test]
fn only_transient_failures_are_retried_by_this_client() {
    assert!(PublishFailure::Transient(TransientClass::Timeout).is_retryable());
    assert!(!PublishFailure::NotAccepted(NotAcceptedReason::UnversionedResponse).is_retryable());
    assert!(!PublishFailure::Terminal(TerminalClass::ScopeMismatch).is_retryable());
}

#[test]
fn every_failure_label_pair_is_low_cardinality_and_stable() {
    // A label built from a formatted value rather than a fixed string would
    // let a repository or event id reach a metric dimension. Both halves are
    // `&'static str` by construction; this pins that they stay non-empty and
    // free of interpolation markers.
    for failure in [
        PublishFailure::NotAccepted(NotAcceptedReason::IncompleteAcceptanceEvidence),
        PublishFailure::Transient(TransientClass::StreamFull),
        PublishFailure::Transient(TransientClass::IdentityRejected),
        PublishFailure::Terminal(TerminalClass::ScopeMismatch),
    ] {
        assert!(!failure.family_label().is_empty());
        assert!(!failure.class_label().is_empty());
        assert!(!failure.class_label().contains('{'));
    }
}
