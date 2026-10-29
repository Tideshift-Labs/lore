// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_base::error::AddressNotFound;
use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_error_set::ForwardStrict;
use lore_revision::branch::push::*;
use lore_revision::event::EventError;
use lore_revision::interface::LoreError;
use lore_revision::repository::RepositoryContext;
use lore_transport::ProtocolError;
use lore_transport::quic::storage_service::QueryStatus;

fn address(seed: u8) -> Address {
    Address {
        hash: Hash::from([seed; 32]),
        context: lore_base::types::Context::from([seed; 16]),
    }
}

/// Statistics level zero reports nothing, so it keeps nothing beyond what a
/// progress event reads: the fragments registered, which `copied` and `put`
/// sum to, and the bytes uploaded.
#[test]
fn a_count_is_kept_only_where_something_reports_it() {
    for (statistics, deduplicated) in [(false, 0), (true, 3)] {
        let stats = PushStats::new(statistics);
        stats.deduplicated(3);
        stats.copied();
        stats.put(64);

        let counts = stats.snapshot();
        assert_eq!(counts.deduplicated, deduplicated, "statistics {statistics}");
        assert_eq!(counts.copied, 1, "statistics {statistics}");
        assert_eq!(counts.put, 1, "statistics {statistics}");
        assert_eq!(stats.registered(), 2, "statistics {statistics}");
        assert_eq!(stats.put_bytes(), 64, "statistics {statistics}");
    }
}

/// A fragment the peer is missing reaches the caller as the address it is, rather than as a
/// generic failure.
#[test]
fn a_fragment_the_peer_is_missing_keeps_its_address_on_the_way_out() {
    let result: Result<(), ProtocolError> =
        Err(ProtocolError::from(AddressNotFound { address: [7u8; 48] }));

    let error = result
        .forward::<PushError>("pushing branch to remote, missing fragment")
        .expect_err("an error was forwarded");

    assert!(error.is_address_not_found(), "{error:?}");
    assert!(error.translated() == LoreError::AddressNotFound);
}

/// What the push does with a fragment is decided entirely by the status byte the peer answered
/// with, so this is where the copy path is chosen or missed.
mod classify {
    use super::*;

    fn classify(statuses: &[u8]) -> PushQueryResult {
        let batch: Vec<Address> = (0..statuses.len() as u8).map(address).collect();
        let mut queried = PushQueryResult::default();
        classify_query_batch(&batch, &Bytes::copy_from_slice(statuses), &mut queried);
        queried
    }

    /// A full match transfers nothing, but the answer still has to be kept: it is what tells
    /// the local store the payload is safe elsewhere, and an entry that never learns that is
    /// pinned against eviction and invisible to both store caps for the rest of its life.
    #[test]
    fn an_association_the_peer_holds_transfers_nothing_but_is_recorded() {
        let queried = classify(&[QueryStatus::ExistFullMatch as u8]);
        assert_eq!(queried.len(), 0, "nothing to transfer");
        assert_eq!(queried.present, vec![address(0)]);
    }

    /// The change this path exists for: the partition holds the hash, so the peer is asked to
    /// duplicate the association rather than sent the payload it already has.
    #[test]
    fn a_partition_match_is_copied_rather_than_uploaded() {
        let queried = classify(&[QueryStatus::ExistPartitionMatch as u8]);
        assert_eq!(queried.copyable, vec![address(0)]);
        assert!(queried.absent.is_empty());
    }

    #[test]
    fn a_miss_is_uploaded() {
        let queried = classify(&[QueryStatus::NotFound as u8]);
        assert_eq!(queried.absent, vec![address(0)]);
        assert!(queried.copyable.is_empty());
    }

    /// A status the client does not know must not be read as "the peer has it" — that would
    /// drop the fragment from the push and leave the revision unreadable on the peer.
    #[test]
    fn an_unknown_status_is_uploaded() {
        let queried = classify(&[2, 7, 255]);
        assert_eq!(queried.absent.len(), 3);
        assert!(queried.copyable.is_empty());
    }

    #[test]
    fn a_batch_is_split_by_status_in_order() {
        let queried = classify(&[
            QueryStatus::NotFound as u8,
            QueryStatus::ExistFullMatch as u8,
            QueryStatus::ExistPartitionMatch as u8,
            QueryStatus::NotFound as u8,
            QueryStatus::ExistPartitionMatch as u8,
        ]);
        assert_eq!(queried.absent, vec![address(0), address(3)]);
        assert_eq!(queried.copyable, vec![address(2), address(4)]);
        assert_eq!(queried.present, vec![address(1)]);
        assert_eq!(queried.len(), 4, "len counts only what is transferred");
    }

    /// Each status answers the address at its own position, so a batch where only some entries
    /// are copyable must not shift the rest.
    #[test]
    fn statuses_line_up_with_the_addresses_they_answer() {
        let queried = classify(&[
            QueryStatus::ExistPartitionMatch as u8,
            QueryStatus::ExistFullMatch as u8,
            QueryStatus::NotFound as u8,
        ]);
        assert_eq!(queried.copyable, vec![address(0)]);
        assert_eq!(queried.present, vec![address(1)]);
        assert_eq!(queried.absent, vec![address(2)]);
    }
}

/// Recording a full match is what takes the fragment off the local store's protected list, so
/// this is where a push stops re-offering content the peer already holds.
mod mark {
    use super::*;

    const DURABLE: u32 = lore_base::types::FragmentFlags::PayloadStoredDurable.bits();

    /// A repository over in-memory stores, holding only what the test puts in it.
    async fn null_repository() -> Arc<RepositoryContext> {
        let immutable_store = lore_storage::local::immutable_store::create(
            None::<&str>,
            lore_storage::local::immutable_store::ImmutableStoreCreateOptions::none(),
            false,
            lore_storage::ImmutableStoreSettings::default(),
        )
        .await
        .expect("in-memory immutable store");
        let mutable_store = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            immutable_store.clone(),
        )
        .await
        .expect("in-memory mutable store");

        Arc::new(RepositoryContext::new_null_context(
            immutable_store,
            mutable_store,
        ))
    }

    /// Store a payload under `address` carrying no durability, as a local commit leaves it.
    async fn store_local(repository: &Arc<RepositoryContext>, address: Address) {
        let payload = Bytes::from_static(b"payload");
        let fragment = Fragment {
            flags: 0,
            size_payload: payload.len() as u32,
            size_content: payload.len() as u64,
        };
        repository
            .immutable_store()
            .put(repository.id, address, fragment, Some(payload), false)
            .await
            .expect("storing a local payload");
    }

    /// The flags the store holds for `address`.
    async fn stored_flags(repository: &Arc<RepositoryContext>, address: Address) -> u32 {
        repository
            .immutable_store()
            .get_metadata(repository.id, address)
            .await
            .expect("the store holds the address")
            .fragment
            .flags
    }

    /// The fact a full match establishes: the payload is safe on the peer, so the local entry
    /// is no longer the only copy.
    #[tokio::test]
    async fn a_present_address_becomes_durable() {
        let repository = null_repository().await;
        let present = address(1);
        store_local(&repository, present).await;
        assert_eq!(
            stored_flags(&repository, present).await & DURABLE,
            0,
            "a locally stored payload starts out non-durable"
        );

        mark_present_durable(&repository, vec![present]).await;

        assert_eq!(stored_flags(&repository, present).await & DURABLE, DURABLE);
    }

    /// An address the store cannot describe answers nothing to write back, and must not cost
    /// the addresses it can describe their record.
    #[tokio::test]
    async fn a_batch_marks_what_it_can_and_skips_the_rest() {
        let repository = null_repository().await;
        let present = address(2);
        store_local(&repository, present).await;

        mark_present_durable(&repository, vec![address(0), address(3), present]).await;

        assert_eq!(
            stored_flags(&repository, present).await & DURABLE,
            DURABLE,
            "a zero hash and an address the store never held are skipped, not fatal"
        );
    }
}

/// A failed Copy falls back to uploading the payload only when the refusal is decisive. A Copy
/// that may have applied (an unknown outcome, or the lost answer of an unjournaled managed Copy)
/// must fail the push: an upload would be a second mutation for the same address.
mod copy_fallback {
    use lore_base::error::AddressNotFound;
    use lore_base::error::Disconnected;
    use lore_transport::outcome::AttemptId;
    use lore_transport::outcome::GrpcRpc;
    use lore_transport::outcome::outcome_unknown;

    use super::*;

    #[test]
    fn a_decisive_refusal_allows_the_upload_fallback() {
        for error in [
            ProtocolError::from(AddressNotFound { address: [7u8; 48] }),
            ProtocolError::from(tonic::Status::permission_denied("no")),
            ProtocolError::from(tonic::Status::not_found("no source")),
            ProtocolError::internal("the source fragment is missing"),
            // Disconnected after `resolve` is proof the Copy was never dispatched, so it is not a
            // lost answer and the upload may follow.
            ProtocolError::from(Disconnected),
        ] {
            assert!(copy_failure_allows_upload(&error), "{error:?}");
        }
    }

    #[test]
    fn an_unknown_outcome_forbids_the_upload_fallback() {
        let error = outcome_unknown(GrpcRpc::StorageCopy.wire_name(), &AttemptId::new());
        assert!(error.is_outcome_unknown());
        assert!(!copy_failure_allows_upload(&error), "{error:?}");
    }

    #[tokio::test]
    async fn a_lost_unjournaled_copy_answer_forbids_the_upload_fallback() {
        // Produce the real lost-answer error through the transport's own mapping.
        let attempt = AttemptId::new();
        let lost = lore_transport::grpc::storage_client::unjournaled_result(
            GrpcRpc::StorageCopy,
            Err(ProtocolError::from(tonic::Status::cancelled("answer lost"))),
            &attempt,
        )
        .expect_err("a lost answer is an error");
        assert!(
            lore_transport::is_unjournaled_answer_lost(&lost),
            "{lost:?}"
        );
        assert!(!lost.is_outcome_unknown(), "{lost:?}");
        assert!(!copy_failure_allows_upload(&lost), "{lost:?}");
    }

    /// A managed command that was not sent because the reconnect expired is not a decisive refusal
    /// of the Copy: the connection is still down, so an upload would only spend another bound.
    #[test]
    fn a_managed_reconnect_expiry_forbids_the_upload_fallback() {
        let expired = lore_transport::managed_reconnect_expired_for_test("Copy");
        assert!(
            lore_transport::is_managed_reconnect_expired(&expired),
            "{expired:?}"
        );
        assert!(!copy_failure_allows_upload(&expired), "{expired:?}");
    }
}

/// How the managed reconnect expiry reads once the push forwards it into its own error set.
mod reconnect_expiry_translation {
    use lore_transport::outcome::AttemptId;
    use lore_transport::outcome::GrpcRpc;

    use super::*;

    /// Forward the way the push does: `forward` into `PushError`, then translate for the caller.
    fn translated(error: ProtocolError) -> (PushError, LoreError) {
        let forwarded = Err::<(), ProtocolError>(error)
            .forward::<PushError>("pushing branch to remote")
            .expect_err("an error was forwarded");
        let translated = forwarded.translated();
        (forwarded, translated)
    }

    /// The push forwards the marker either of two ways: `forward` (the read paths) or
    /// `internal_with_context` (the Put path). Both are converted by the function the three remote
    /// phases are mapped through.
    #[test]
    fn a_not_sent_expiry_reads_disconnected_whichever_way_it_was_forwarded() {
        use lore_error_set::FfiError;

        let forwarded =
            Err::<(), ProtocolError>(lore_transport::managed_reconnect_expired_for_test("Get"))
                .forward::<PushError>("pushing branch to remote")
                .expect_err("an error was forwarded");
        let wrapped = PushError::internal_with_context(
            lore_transport::managed_reconnect_expired_for_test("Put"),
            "putting fragment to remote",
        );
        for (how, error) in [("forward", forwarded), ("internal_with_context", wrapped)] {
            assert_eq!(error.ffi_code(), -1, "{how}: starts as Internal");
            let converted = not_sent_reads_disconnected(error);
            assert_eq!(
                converted.ffi_code(),
                lore_base::error::Disconnected::FFI_CODE,
                "{how}: {converted:?}"
            );
            assert_eq!(lore_base::error::Disconnected::FFI_CODE, 28);
            assert!(converted.translated() == LoreError::Connection, "{how}");
        }
    }

    /// A lost answer may have applied: it keeps its own error and code.
    #[tokio::test]
    async fn a_lost_unjournaled_answer_passes_through_not_sent_reads_disconnected() {
        use lore_error_set::FfiError;

        let attempt = AttemptId::new();
        let lost = lore_transport::grpc::storage_client::unjournaled_result(
            GrpcRpc::StoragePut,
            Err(ProtocolError::from(tonic::Status::cancelled("answer lost"))),
            &attempt,
        )
        .expect_err("a lost answer is an error");
        let error = PushError::internal_with_context(lost, "putting fragment to remote");
        let converted = not_sent_reads_disconnected(error);
        assert_eq!(converted.ffi_code(), -1, "{converted:?}");
        assert!(
            converted.translated() == LoreError::Internal,
            "{converted:?}"
        );
    }

    /// An unknown outcome stays unknown: converting it would tell the caller nothing happened.
    #[test]
    fn an_unknown_outcome_passes_through_not_sent_reads_disconnected() {
        use lore_error_set::FfiError;

        let unknown = PushError::from(lore_base::error::OutcomeUnknown {
            operation: "StorageService.Put".to_string(),
            attempt_id: "attempt".to_string(),
        });
        let expected = unknown.ffi_code();
        let converted = not_sent_reads_disconnected(unknown);
        assert!(converted.is_outcome_unknown(), "{converted:?}");
        assert_eq!(converted.ffi_code(), expected);
        assert!(converted.translated() == LoreError::OutcomeUnknown);
    }

    #[test]
    fn a_managed_reconnect_expiry_translates_to_a_connection_error() {
        let expired = lore_transport::managed_reconnect_expired_for_test("Put");
        let (forwarded, translated) = translated(expired);
        assert!(translated == LoreError::Connection, "{forwarded:?}");
    }

    /// Pin: a lost answer may have applied, so it must not read as a lost connection.
    #[tokio::test]
    async fn a_lost_unjournaled_answer_does_not_translate_to_a_connection_error() {
        let attempt = AttemptId::new();
        let lost = lore_transport::grpc::storage_client::unjournaled_result(
            GrpcRpc::StoragePut,
            Err(ProtocolError::from(tonic::Status::cancelled("answer lost"))),
            &attempt,
        )
        .expect_err("a lost answer is an error");
        assert!(
            lore_transport::is_unjournaled_answer_lost(&lost),
            "{lost:?}"
        );
        let (forwarded, translated) = translated(lost);
        assert!(translated == LoreError::Internal, "{forwarded:?}");
    }
}
