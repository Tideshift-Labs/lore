// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::lock::util::*;

#[test]
fn fold_batch_results_collects_every_batch() {
    let (items, num_success, first_error) =
        fold_batch_results::<u32, String>(vec![Ok(vec![1, 2]), Ok(vec![]), Ok(vec![3])], 3);

    assert_eq!(items, vec![1, 2, 3]);
    assert_eq!(num_success, 3);
    assert!(first_error.is_none());
}

#[test]
fn fold_batch_results_reserves_the_requested_capacity() {
    let (items, _, _) = fold_batch_results::<u32, String>(vec![Ok(vec![1])], 64);

    assert!(
        items.capacity() >= 64,
        "capacity {} was not reserved up front",
        items.capacity()
    );
}

#[test]
fn fold_batch_results_keeps_one_error_and_the_successful_items() {
    let (items, num_success, first_error) = fold_batch_results::<u32, String>(
        vec![
            Ok(vec![1]),
            Err("first".to_string()),
            Err("second".to_string()),
            Ok(vec![2]),
        ],
        2,
    );

    assert_eq!(items, vec![1, 2]);
    assert_eq!(num_success, 2);
    assert_eq!(first_error, Some("first".to_string()));
}

#[test]
fn fold_batch_results_reports_no_error_without_batches() {
    let (items, num_success, first_error) = fold_batch_results::<u32, String>(vec![], 0);

    assert!(items.is_empty());
    assert_eq!(num_success, 0);
    assert!(first_error.is_none());
}

/// How a lock verb's remote error reads once `not_sent_reads_disconnected` has seen it.
mod not_sent_reads_disconnected_tests {
    use lore_error_set::FfiError;
    use lore_error_set::ForwardStrict;
    use lore_revision::lock::file::acquire::AcquireError;
    use lore_revision::lock::file::release::ReleaseError;
    use lore_transport::ProtocolError;

    use super::*;

    fn expired() -> ProtocolError {
        lore_transport::managed_reconnect_expired_for_test("session")
    }

    /// The marker is forwarded the way both verbs forward `remote()`'s error, then converted.
    fn check_marker_becomes_disconnected<E>(verb: &str, forward: fn(ProtocolError) -> E)
    where
        E: lore_error_set::ErrorSet + From<lore_base::error::Disconnected> + FfiError,
    {
        let forwarded = forward(expired());
        assert_eq!(forwarded.ffi_code(), -1, "{verb}: starts as Internal");
        let converted = not_sent_reads_disconnected(forwarded);
        assert_eq!(
            converted.ffi_code(),
            lore_base::error::Disconnected::FFI_CODE,
            "{verb}"
        );
        assert_eq!(lore_base::error::Disconnected::FFI_CODE, 28);
    }

    #[test]
    fn a_forwarded_marker_becomes_ffi_28_for_both_verbs() {
        check_marker_becomes_disconnected("acquire", |error| {
            Err::<(), _>(error)
                .forward::<AcquireError>("Unable to acquire lock while offline")
                .expect_err("forwarded")
        });
        check_marker_becomes_disconnected("release", |error| {
            Err::<(), _>(error)
                .forward::<ReleaseError>("Unable to release lock while offline")
                .expect_err("forwarded")
        });
    }

    #[test]
    fn a_plain_internal_keeps_its_code_for_both_verbs() {
        let acquire = not_sent_reads_disconnected(AcquireError::internal("plain"));
        assert_eq!(acquire.ffi_code(), -1, "{acquire:?}");
        let release = not_sent_reads_disconnected(ReleaseError::internal("plain"));
        assert_eq!(release.ffi_code(), -1, "{release:?}");
    }

    #[test]
    fn an_unknown_outcome_stays_unknown_for_both_verbs() {
        let unknown = || lore_base::error::OutcomeUnknown {
            operation: "LockService.Lock".to_string(),
            attempt_id: "attempt".to_string(),
        };
        let acquire_in = AcquireError::from(unknown());
        let expected = acquire_in.ffi_code();
        let acquire = not_sent_reads_disconnected(acquire_in);
        assert!(
            matches!(acquire, AcquireError::OutcomeUnknown(_)),
            "{acquire:?}"
        );
        assert_eq!(acquire.ffi_code(), expected);

        let release_in = ReleaseError::from(unknown());
        let expected = release_in.ffi_code();
        let release = not_sent_reads_disconnected(release_in);
        assert!(
            matches!(release, ReleaseError::OutcomeUnknown(_)),
            "{release:?}"
        );
        assert_eq!(release.ffi_code(), expected);
    }
}
