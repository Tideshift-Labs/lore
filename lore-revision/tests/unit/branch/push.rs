// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_base::error::AddressNotFound;
use lore_base::error::Disconnected;
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

/// An offer the peer refuses onto a branch holding revisions the local history does not is a
/// divergence. Any other failure keeps its own variant.
#[test]
fn a_refused_offer_is_divergent_only_onto_a_diverged_branch() {
    let refused = || PushError::internal("remote rejected the request");

    let error = refused_offer(refused(), true);
    assert!(error.is_divergent(), "{error:?}");

    let error = refused_offer(refused(), false);
    assert!(error.is_internal(), "{error:?}");

    let error = refused_offer(PushError::from(Disconnected), true);
    assert!(error.is_disconnected(), "{error:?}");
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

/// Recording a full match is what takes the fragment off the local store's protected list, so
/// this is where a push stops re-offering content the peer already holds.
mod mark {
    use super::*;

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

/// FORK-LOCAL (Tideshift, A6): a `BranchPush` the server refused with a transient verdict that
/// proves it did not apply is sent again, within a small budget, and nothing else is.
mod transient_push_verdict {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use lore_base::error::AddressNotFound;
    use lore_base::error::OutcomeUnknown;
    use lore_revision::branch::push::*;
    use lore_transport::ProtocolError;

    /// A scripted transport: each send takes the next answer. A send past the script fails with
    /// a distinct refusal, so a loop that ignores its budget ends with a wrong count, not a hang.
    struct Script {
        answers: parking_lot::Mutex<VecDeque<Result<u32, ProtocolError>>>,
        sends: AtomicUsize,
    }

    impl Script {
        fn new(answers: Vec<Result<u32, ProtocolError>>) -> Arc<Self> {
            Arc::new(Self {
                answers: parking_lot::Mutex::new(answers.into()),
                sends: AtomicUsize::new(0),
            })
        }

        fn sends(&self) -> usize {
            self.sends.load(Ordering::SeqCst)
        }
    }

    /// The production budget, with no waiting.
    fn budget() -> PushVerdictBudget {
        PushVerdictBudget::new(lore_revision::util::time::retry(
            0,
            0,
            BRANCH_PUSH_VERDICT_ATTEMPTS - 1,
        ))
    }

    impl Script {
        /// One send: take the next answer.
        fn send(self: &Arc<Self>) -> impl Future<Output = Result<u32, ProtocolError>> + use<> {
            let script = self.clone();
            async move {
                script.sends.fetch_add(1, Ordering::SeqCst);
                script
                    .answers
                    .lock()
                    .pop_front()
                    .unwrap_or_else(|| Err(ProtocolError::internal("script exhausted")))
            }
        }
    }

    async fn run(
        script: &Arc<Script>,
        transport_retries_slow_down: bool,
    ) -> Result<u32, ProtocolError> {
        retry_transient_push_verdict(&mut budget(), transport_retries_slow_down, || script.send())
            .await
    }

    fn required_fragment_changed() -> ProtocolError {
        ProtocolError::from(tonic::Status::aborted("required_fragment_changed"))
    }

    fn verdict_changed() -> ProtocolError {
        // What the server's `verdict_changed` SlowDown reaches the client as.
        ProtocolError::from(tonic::Status::resource_exhausted("verdict_changed"))
    }

    #[test]
    fn the_budget_is_three_attempts() {
        assert_eq!(BRANCH_PUSH_VERDICT_ATTEMPTS, 3);
        assert_eq!(branch_push_verdict_retry().limit(), 2);
    }

    #[tokio::test]
    async fn a_required_fragment_change_then_success_succeeds_on_the_second_send() {
        let script = Script::new(vec![Err(required_fragment_changed()), Ok(7)]);
        assert_eq!(run(&script, false).await.unwrap(), 7);
        assert_eq!(script.sends(), 2);
    }

    #[tokio::test]
    async fn a_required_fragment_change_is_retried_even_where_the_transport_retries_slow_down() {
        let script = Script::new(vec![Err(required_fragment_changed()), Ok(7)]);
        assert_eq!(run(&script, true).await.unwrap(), 7);
        assert_eq!(script.sends(), 2);
    }

    #[tokio::test]
    async fn a_verdict_change_then_success_succeeds_on_the_second_send() {
        let script = Script::new(vec![Err(verdict_changed()), Ok(7)]);
        assert_eq!(run(&script, false).await.unwrap(), 7);
        assert_eq!(script.sends(), 2);
    }

    #[tokio::test]
    async fn an_exhausted_budget_surfaces_the_servers_refusal() {
        let script = Script::new((0..10).map(|_| Err(required_fragment_changed())).collect());
        let error = run(&script, false).await.unwrap_err();
        assert!(
            lore_transport::is_required_fragment_changed(&error),
            "{error:?}"
        );
        assert_eq!(script.sends(), BRANCH_PUSH_VERDICT_ATTEMPTS);
    }

    /// The server already waits out `SlowDown` inside each send, so a `SlowDown` buys one resend.
    #[tokio::test]
    async fn slow_down_is_resent_at_most_once() {
        assert_eq!(BRANCH_PUSH_SLOW_DOWN_RESENDS, 1);

        let script = Script::new(vec![Err(verdict_changed()), Err(verdict_changed()), Ok(7)]);
        let error = run(&script, false).await.unwrap_err();
        assert!(error.is_slow_down(), "{error:?}");
        assert_eq!(script.sends(), 2);

        // A required-fragment change spends the general budget, not the `SlowDown` resend.
        let script = Script::new(vec![
            Err(required_fragment_changed()),
            Err(verdict_changed()),
            Ok(7),
        ]);
        assert_eq!(run(&script, false).await.unwrap(), 7);
        assert_eq!(script.sends(), 3);

        let script = Script::new(vec![
            Err(verdict_changed()),
            Err(required_fragment_changed()),
            Err(verdict_changed()),
            Ok(7),
        ]);
        assert!(run(&script, false).await.unwrap_err().is_slow_down());
        assert_eq!(script.sends(), 3);
    }

    /// One budget spans a revision's sends: the push after a server-side branch recreate does not
    /// start a fresh one, and still sends once.
    #[tokio::test]
    async fn a_shared_budget_carries_across_calls() {
        let mut shared = budget();
        let script = Script::new(vec![
            Err(required_fragment_changed()),
            Err(ProtocolError::from(tonic::Status::not_found(
                "Branch not found",
            ))),
            Err(required_fragment_changed()),
            Err(required_fragment_changed()),
            Ok(7),
        ]);
        let first = retry_transient_push_verdict(&mut shared, false, || script.send()).await;
        assert!(
            matches!(first, Err(ProtocolError::NotFound(_))),
            "{first:?}"
        );
        assert_eq!(script.sends(), 2);
        let second = retry_transient_push_verdict(&mut shared, false, || script.send()).await;
        assert!(
            lore_transport::is_required_fragment_changed(&second.unwrap_err()),
            "the recreate push had one resend left"
        );
        assert_eq!(script.sends(), 4);
    }

    #[tokio::test]
    async fn a_mixed_run_of_transient_verdicts_shares_one_budget() {
        let script = Script::new(vec![
            Err(required_fragment_changed()),
            Err(verdict_changed()),
            Err(required_fragment_changed()),
            Ok(7),
        ]);
        let error = run(&script, false).await.unwrap_err();
        assert!(
            lore_transport::is_required_fragment_changed(&error),
            "{error:?}"
        );
        assert_eq!(script.sends(), BRANCH_PUSH_VERDICT_ATTEMPTS);
    }

    #[tokio::test]
    async fn a_non_retryable_refusal_is_sent_once() {
        let refusals = [
            ProtocolError::from(tonic::Status::permission_denied("protected")),
            ProtocolError::from(tonic::Status::aborted(
                "required_fragment_proof_unavailable",
            )),
            ProtocolError::from(tonic::Status::aborted(
                "Branch preflight changed; rerun preflight",
            )),
            ProtocolError::from(tonic::Status::not_found("Branch not found")),
            ProtocolError::from(AddressNotFound { address: [7u8; 48] }),
            ProtocolError::internal("remote rejected the request"),
        ];
        for refusal in refusals {
            let rendered = refusal.to_string();
            let script = Script::new(vec![Err(refusal), Ok(7)]);
            assert!(run(&script, false).await.is_err(), "{rendered}");
            assert_eq!(script.sends(), 1, "{rendered}");
        }
    }

    /// The unmanaged gRPC client already loops on `SlowDown` inside the RPC.
    #[tokio::test]
    async fn slow_down_is_sent_once_where_the_transport_already_retried_it() {
        let script = Script::new(vec![Err(verdict_changed()), Ok(7)]);
        assert!(run(&script, true).await.unwrap_err().is_slow_down());
        assert_eq!(script.sends(), 1);
    }

    /// The replay contract: a dispatch that may have applied is never sent again.
    #[tokio::test]
    async fn an_unknown_outcome_or_a_lost_answer_is_sent_once() {
        let mut marked = tonic::Status::aborted("required_fragment_changed");
        marked.metadata_mut().insert(
            lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
            lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_VALUE
                .parse()
                .unwrap(),
        );
        let lost = [
            ProtocolError::from(OutcomeUnknown {
                operation: "RevisionService.BranchPush".into(),
                attempt_id: "fixture".into(),
            }),
            ProtocolError::from(marked),
            ProtocolError::from(tonic::Status::unavailable("gone")),
            ProtocolError::from(tonic::Status::cancelled("answer lost")),
        ];
        for error in lost {
            let rendered = format!("{error:?}");
            let script = Script::new(vec![Err(error), Ok(7)]);
            assert!(run(&script, false).await.is_err(), "{rendered}");
            assert_eq!(script.sends(), 1, "{rendered}");
        }
    }

    /// The call site `push_local_history` uses, under a real `ManagedPushRunner` (the desktop's
    /// path) and without one (the stock CLI's).
    mod call_site {
        use std::sync::Arc;

        use lore_base::types::RepositoryId;
        use lore_revision::managed_push::ManagedPushRunner;
        use lore_revision::repository_fence::RepositoryMutationGuard;
        use lore_transport::AttemptId;
        use uuid::Uuid;

        use super::*;

        const REPOSITORY: [u8; 16] = [5; 16];

        /// Each send as the transport saw it: its stage and its attempt id.
        type Sends = Arc<parking_lot::Mutex<Vec<(Option<Uuid>, Option<AttemptId>)>>>;

        #[allow(clippy::disallowed_methods)] // This test's owned temporary worktree only.
        async fn managed_runner() -> (tempfile::TempDir, Arc<ManagedPushRunner>) {
            let directory = tempfile::tempdir().unwrap();
            std::fs::create_dir(directory.path().join(".lore")).unwrap();
            let guard = Arc::new(
                RepositoryMutationGuard::acquire(directory.path())
                    .await
                    .unwrap(),
            );
            (directory, Arc::new(ManagedPushRunner::new(guard, None)))
        }

        async fn send(
            runner: Option<&Arc<ManagedPushRunner>>,
            answers: Vec<Result<u32, ProtocolError>>,
        ) -> (Result<u32, ProtocolError>, Sends) {
            let script = Script::new(answers);
            let sends = Sends::default();
            let result = send_branch_push(
                runner,
                None,
                RepositoryId::from(REPOSITORY),
                &mut budget(),
                || {
                    let sends = sends.clone();
                    let answer = script.send();
                    async move {
                        sends.lock().push((
                            lore_transport::current_caller_operation()
                                .map(|context| context.parent_id()),
                            lore_transport::outcome::current_dispatch_attempt(),
                        ));
                        answer.await
                    }
                },
            )
            .await;
            (result, sends)
        }

        /// Every send ran in its own stage under its own attempt id.
        fn assert_distinct_stages(sends: &Sends, count: usize) {
            let sends = sends.lock();
            assert_eq!(sends.len(), count, "{sends:?}");
            let parents: std::collections::HashSet<_> = sends
                .iter()
                .map(|(parent, _)| parent.expect("a managed stage"))
                .collect();
            let attempts: std::collections::HashSet<_> = sends
                .iter()
                .map(|(_, attempt)| attempt.expect("an attempt id"))
                .collect();
            assert_eq!(parents.len(), count, "{sends:?}");
            assert_eq!(attempts.len(), count, "{sends:?}");
        }

        #[tokio::test]
        async fn managed_slow_down_then_success_sends_twice_with_new_attempts() {
            let (_directory, runner) = managed_runner().await;
            let (result, sends) = send(Some(&runner), vec![Err(verdict_changed()), Ok(7)]).await;
            assert_eq!(result.unwrap(), 7);
            assert_distinct_stages(&sends, 2);
        }

        #[tokio::test]
        async fn managed_slow_down_twice_surfaces_slow_down_after_two_sends() {
            let (_directory, runner) = managed_runner().await;
            let (result, sends) = send(
                Some(&runner),
                vec![Err(verdict_changed()), Err(verdict_changed()), Ok(7)],
            )
            .await;
            assert!(result.unwrap_err().is_slow_down());
            assert_distinct_stages(&sends, 2);
        }

        #[tokio::test]
        async fn managed_required_fragment_change_twice_then_success_sends_three_times() {
            let (_directory, runner) = managed_runner().await;
            let (result, sends) = send(
                Some(&runner),
                vec![
                    Err(required_fragment_changed()),
                    Err(required_fragment_changed()),
                    Ok(7),
                ],
            )
            .await;
            assert_eq!(result.unwrap(), 7);
            assert_distinct_stages(&sends, 3);
        }

        /// The stock CLI's gRPC client already looped on `SlowDown` inside the RPC.
        #[tokio::test]
        async fn unmanaged_slow_down_is_sent_once() {
            let (result, sends) = send(None, vec![Err(verdict_changed()), Ok(7)]).await;
            assert!(result.unwrap_err().is_slow_down());
            assert_eq!(sends.lock().len(), 1);
        }
    }
}

/// What an offer of a revision as a branch's latest does with each answer of the peer.
mod offer {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use async_trait::async_trait;
    use lore_base::error::NotFound;
    use lore_base::types::BranchId;
    use lore_base::types::BranchMetadata;
    use lore_base::types::BranchPoint;
    use lore_base::types::RepositoryId;
    use lore_transport::BranchListResponse;
    use lore_transport::BranchPushResponse;
    use lore_transport::BranchQueryResponse;
    use lore_transport::MetadataSetResult;
    use lore_transport::Revision;
    use lore_transport::RevisionListResponse;
    use lore_transport::RevisionListStart;
    use parking_lot::Mutex;

    use super::*;
    use crate::branch::with_execution;

    /// A peer that answers each branch push with the next of its answers, and counts the
    /// branches it creates.
    struct Peer {
        answers: Mutex<VecDeque<Result<BranchPushResponse, ProtocolError>>>,
        created: AtomicUsize,
    }

    #[async_trait]
    impl Revision for Peer {
        async fn branch_create(
            &self,
            _: BranchId,
            _: &str,
            _: &str,
            _: &str,
            _: &[BranchPoint],
        ) -> Result<Hash, ProtocolError> {
            self.created.fetch_add(1, Ordering::Relaxed);
            Ok(Hash::default())
        }

        async fn branch_delete(&self, _: BranchId) -> Result<(), ProtocolError> {
            unreachable!("an offer deletes no branch")
        }

        async fn branch_query(
            &self,
            _: Option<BranchId>,
            _: Option<&str>,
        ) -> Result<BranchQueryResponse, ProtocolError> {
            unreachable!("an offer queries no branch")
        }

        async fn branch_push(
            &self,
            _: BranchId,
            _: Hash,
            _: bool,
            _: bool,
        ) -> Result<BranchPushResponse, ProtocolError> {
            self.answers
                .lock()
                .pop_front()
                .expect("the peer was not offered more than it answers")
        }

        async fn branch_list(&self) -> Result<BranchListResponse, ProtocolError> {
            unreachable!("an offer lists no branches")
        }

        async fn revision_list(
            &self,
            _: RevisionListStart,
        ) -> Result<RevisionListResponse, ProtocolError> {
            unreachable!("an offer lists no revisions")
        }

        async fn branch_metadata_get(&self, _: BranchId) -> Result<Hash, ProtocolError> {
            unreachable!("an offer reads no branch metadata")
        }

        async fn branch_metadata_set(
            &self,
            _: BranchId,
            _: Hash,
            _: Hash,
        ) -> Result<MetadataSetResult, ProtocolError> {
            unreachable!("an offer writes no branch metadata")
        }
    }

    fn accepted() -> Result<BranchPushResponse, ProtocolError> {
        Ok(BranchPushResponse {
            fast_forward_merged: false,
            revision: Hash::from([1; 32]),
            revision_number: 1,
            message: None,
        })
    }

    fn deleted() -> Result<BranchPushResponse, ProtocolError> {
        Err(ProtocolError::from(NotFound))
    }

    fn missing() -> Result<BranchPushResponse, ProtocolError> {
        Err(ProtocolError::from(AddressNotFound { address: [7; 48] }))
    }

    /// The recovery runs once if the peer refuses the first offer or the offer after a deleted
    /// branch is created again for a missing fragment, and for no other answer. A refusal the
    /// recovery does not fix reaches the caller as the missing fragment it is.
    #[tokio::test]
    async fn recovery_runs_once_and_only_after_a_refusal_for_a_missing_fragment() {
        let cases = [
            ("accepted", vec![accepted()], 0, 0, None),
            ("deleted, accepted", vec![deleted(), accepted()], 1, 0, None),
            ("missing, accepted", vec![missing(), accepted()], 0, 1, None),
            (
                "deleted, missing, accepted",
                vec![deleted(), missing(), accepted()],
                1,
                1,
                None,
            ),
            (
                "missing, missing",
                vec![missing(), missing()],
                0,
                1,
                Some(LoreError::AddressNotFound),
            ),
            (
                "deleted, deleted",
                vec![deleted(), deleted()],
                1,
                0,
                Some(LoreError::NotFound),
            ),
        ];
        for (name, answers, created, recovered, error) in cases {
            let peer = Peer {
                answers: Mutex::new(answers.into()),
                created: AtomicUsize::new(0),
            };
            let recoveries = AtomicUsize::new(0);

            let result = with_execution(Box::pin(offer_revision(
                None,
                None,
                &peer,
                RepositoryId::default(),
                BranchId::default(),
                &BranchMetadata::default(),
                Hash::default(),
                Hash::from([1; 32]),
                false,
                false,
                async || {
                    recoveries.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                },
            )))
            .await;

            assert!(
                result.err().map(|error| error.translated()) == error,
                "{name}: the result"
            );
            assert_eq!(
                peer.created.load(Ordering::Relaxed),
                created,
                "{name}: branches created"
            );
            assert_eq!(
                recoveries.load(Ordering::Relaxed),
                recovered,
                "{name}: recoveries"
            );
            assert!(
                peer.answers.lock().is_empty(),
                "{name}: every answer was asked for"
            );
        }
    }
}

/// Asking the peer to duplicate an association it already holds, as a push does before it uploads.
/// The peer answers copy requests with `SlowDown`, a refusal, or success.
mod duplicate_association {
    use lore_base::error::NotFound;
    use lore_transport::test_util::CopyingPeer;

    use super::*;

    /// What the peer was asked for, how the copy ended, and the local entry's flags afterwards.
    struct Duplicated {
        result: Result<bool, PushError>,
        copies: usize,
        copied: u64,
        flags: u32,
    }

    /// Duplicate a locally stored address on a peer that answers as `slow_downs` and `refusal` say.
    async fn duplicate(seed: u8, slow_downs: usize, refusal: Option<ProtocolError>) -> Duplicated {
        let repository = null_repository().await;
        let wanted = address(seed);
        store_local(&repository, wanted).await;
        let peer = CopyingPeer::new(slow_downs, refusal);
        let session = peer.session(repository.id);
        let stats = PushStats::new(false);

        let result = duplicate_association(&repository, &session, wanted, &stats).await;

        Duplicated {
            result,
            copies: peer.copies(),
            copied: stats.snapshot().copied,
            flags: stored_flags(&repository, wanted).await,
        }
    }

    /// A copy the peer throttles and then accepts registers the association and marks the local
    /// entry as durable.
    #[tokio::test(start_paused = true)]
    async fn a_throttled_copy_that_is_accepted_is_recorded_as_durable() {
        let duplicated = duplicate(0xD1, 2, None).await;

        assert!(duplicated.result.expect("the copy is accepted"));
        assert_eq!(duplicated.copies, 3);
        assert_eq!(duplicated.copied, 1);
        assert_eq!(duplicated.flags & DURABLE, DURABLE);
    }

    /// If the peer throttles a copy until retries run out, the push fails with `SlowDown` rather
    /// than uploading the payload.
    #[tokio::test(start_paused = true)]
    async fn a_copy_throttled_through_every_retry_fails_the_push() {
        let duplicated = duplicate(0xD3, usize::MAX, None).await;

        let error = duplicated
            .result
            .expect_err("a copy still throttled fails the push");
        assert!(error.is_slow_down(), "{error:?}");
        assert_eq!(duplicated.copies, lore_storage::store_retry().limit() + 1);
        assert_eq!(duplicated.copied, 0);
        assert_eq!(duplicated.flags & DURABLE, 0);
    }

    /// A copy refused for a reason other than throttling is not retried, and leaves the payload to
    /// be uploaded.
    #[tokio::test(start_paused = true)]
    async fn a_refused_copy_leaves_the_payload_to_upload() {
        let duplicated = duplicate(0xD5, 0, Some(ProtocolError::from(NotFound))).await;

        assert!(!duplicated.result.expect("a refusal is not an error"));
        assert_eq!(duplicated.copies, 1);
        assert_eq!(duplicated.copied, 0);
        assert_eq!(duplicated.flags & DURABLE, 0);
    }
}
