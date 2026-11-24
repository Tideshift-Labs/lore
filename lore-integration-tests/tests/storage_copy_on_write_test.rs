// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Integration tests for the write path duplicating an association instead of transferring a
//! payload.
//!
//! Content the peer already holds under another context or another partition needs an association,
//! not an upload. The write path establishes that from the resolution it already runs per fragment
//! and issues `Copy` where it would have issued `Put`. These tests spin up a real gRPC server whose
//! store counts what it was asked to do, so "no payload was transferred" is observed at the peer
//! rather than inferred from the client.

#[cfg(all(test, feature = "integration_tests"))]
mod storage_copy_on_write_tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use bytes::Bytes;
    use lore::storage::handle::LoreStore;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_base::types::Fragment;
    use lore_base::types::Partition;
    use lore_revision::event::LoreBytes;
    use lore_revision::event::LoreEvent;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreEventCallback;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_storage::ImmutableStore;
    use lore_storage::StoreError;
    use lore_storage::StoreMatch;
    use lore_storage::immutable_store::query_one;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_transport::AttemptStore;

    use crate::common::net_common::CountingStore;
    use crate::common::net_common::Partitions;
    use crate::common::net_common::TestServerStop;
    use crate::common::net_common::Traffic;
    use crate::common::net_common::close_handle;
    use crate::common::net_common::make_backends;
    use crate::common::net_common::open_handle;
    use crate::common::net_common::open_handle_with_globals;
    use crate::common::net_common::put_content;
    use crate::common::net_common::start_grpc_server;
    use crate::setup_execution;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn a_direct_store_unknown_keeps_its_handler_classification() {
        let error = StoreError::from(lore_base::error::OutcomeUnknown {
            operation: "StorageService.Copy".into(),
            attempt_id: uuid::Uuid::now_v7().to_string(),
        });
        let mapped = lore_server::protocol::storage::messages::MessageHandleError::from(error);
        assert!(
            matches!(
                mapped,
                lore_server::protocol::storage::messages::MessageHandleError::OutcomeUnknown
            ),
            "{mapped:?}"
        );
    }

    // Auth-OFF fixture: this token tests caller namespace capture, not authentication.
    const FIXTURE_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

    #[derive(Default)]
    struct ManagedJournal {
        inner: lore_transport::VolatileAttemptStore,
        intents: Mutex<HashMap<uuid::Uuid, lore_transport::caller_operation::ManagedAttemptIntent>>,
    }

    #[async_trait::async_trait]
    impl lore_transport::AttemptStore for ManagedJournal {
        async fn record(
            &self,
            r: &lore_transport::AttemptRecord,
        ) -> Result<(), lore_transport::ProtocolError> {
            self.inner.record(r).await
        }
        async fn record_managed(
            &self,
            r: &lore_transport::AttemptRecord,
            intent: &lore_transport::caller_operation::ManagedAttemptIntent,
        ) -> Result<(), lore_transport::ProtocolError> {
            assert_eq!(r.repository, intent.repository);
            assert_eq!(r.operation, intent.rpc);
            assert!(!intent.canonical_request.is_empty());
            self.inner.record(r).await?;
            self.intents
                .lock()
                .unwrap()
                .insert(r.attempt_id.as_uuid(), intent.clone());
            Ok(())
        }
        async fn lookup(
            &self,
            id: &lore_transport::AttemptId,
        ) -> Result<Option<lore_transport::AttemptRecord>, lore_transport::ProtocolError> {
            self.inner.lookup(id).await
        }
        async fn unresolved(
            &self,
        ) -> Result<Vec<lore_transport::AttemptRecord>, lore_transport::ProtocolError> {
            self.inner.unresolved().await
        }
        async fn record_ownership(
            &self,
            _: &lore_transport::LockOwnership,
        ) -> Result<(), lore_transport::ProtocolError> {
            unreachable!()
        }
        async fn ownership_for(
            &self,
            _: &Context,
            _: &lore_base::types::Hash,
        ) -> Result<Option<lore_transport::LockOwnership>, lore_transport::ProtocolError> {
            unreachable!()
        }
        async fn clear_ownership(
            &self,
            _: &Context,
            _: &lore_base::types::Hash,
        ) -> Result<(), lore_transport::ProtocolError> {
            unreachable!()
        }
        async fn resolve(
            &self,
            id: &lore_transport::AttemptId,
            resolution: lore_transport::AttemptResolution,
        ) -> Result<(), lore_transport::ProtocolError> {
            self.inner.resolve(id, resolution).await
        }
    }

    #[tokio::test]
    async fn a_lost_copy_answer_never_falls_back_to_put_and_fails_the_public_result() -> TestResult
    {
        unknown_copy_public_result(false).await
    }

    #[tokio::test]
    async fn a_lost_copy_answer_fails_only_its_item_in_a_mixed_public_batch() -> TestResult {
        unknown_copy_public_result(true).await
    }

    async fn unknown_copy_public_result(mixed_batch: bool) -> TestResult {
        let execution = setup_execution("copy-unknown-no-fallback".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_server().await;
                let handle = open_handle_with_token(&server, FIXTURE_TOKEN).await;
                // In-flight storage state is process-global, even across independent stores.
                let partition = Partition::from(*uuid::Uuid::now_v7().as_bytes());
                let payload = b"copy was committed but its response was lost".to_vec();
                put_with_token(
                    handle,
                    partition,
                    Context::from([0x82; 16]),
                    &payload,
                    1,
                    0,
                    FIXTURE_TOKEN,
                )
                .await;
                server.counted.reset();
                server
                    .counted
                    .lose_copy_response
                    .store(true, Ordering::SeqCst);
                let journal = Arc::new(ManagedJournal::default());
                let operation = lore_transport::caller_operation::CallerOperationContext::new(
                    uuid::Uuid::now_v7(),
                    partition,
                    journal.clone(),
                );
                let events = Arc::new(Mutex::new(Vec::new()));
                let sink = events.clone();
                let completions = Arc::new(Mutex::new(Vec::new()));
                let complete_sink = completions.clone();
                let callback: LoreEventCallback = Some(Box::new(move |event| {
                    if let LoreEvent::StoragePutItemComplete(data) = event {
                        sink.lock().unwrap().push((data.id, data.error.error_code));
                    }
                    if let LoreEvent::Complete(data) = event {
                        complete_sink.lock().unwrap().push(serde_json::to_string(data).unwrap());
                    }
                }));
                let mut items = vec![lore::storage::put::LoreStoragePutItem {
                    id: 1,
                    partition,
                    context: Context::from([0x83; 16]),
                    data: LoreBytes {
                        ptr: payload.as_ptr().cast(),
                        len: payload.len(),
                    },
                    remote_write: 1,
                    local_cache: 0,
                    fixed_size_chunk: 0,
remote_query: 0,
}];
                if mixed_batch {
                    items.push(lore::storage::put::LoreStoragePutItem {
                        id: 2,
                        partition: Partition::default(),
                        ..items[0]
                    });
                    items.push(lore::storage::put::LoreStoragePutItem {
                        id: 3,
                        data: LoreBytes {
                            ptr: std::ptr::null(),
                            len: 0,
                        },
                        ..items[0]
                    });
                }
                let status = lore_transport::caller_operation::with_caller_operation(
                    operation,
                    lore::storage::put::put(
                        LoreGlobalArgs {
                            access_token: LoreString::from(FIXTURE_TOKEN),
                            ..Default::default()
                        },
                        lore::storage::put::LoreStoragePutArgs {
                            handle,
                            items: LoreArray::from_vec(items),
                        },
                        callback,
                    ),
                )
                .await;
                let event_snapshot = events.lock().unwrap().clone();
                let completion_snapshot = completions.lock().unwrap().clone();
                let unresolved_snapshot = journal.unresolved().await.unwrap();
                assert_eq!(server.counted.traffic().copies, 1,
                    "fixture must reach Copy before testing response-loss propagation; status={status}, events={event_snapshot:?}, unresolved={unresolved_snapshot:?}, completions={completion_snapshot:?}");
                // A managed Copy writes no journal child, so its lost answer is a plain failed
                // write rather than an unknown outcome: the push fails, retryably, and holds no
                // fence.
                let outcome_unknown = lore_revision::interface::LoreError::OutcomeUnknown as i32;
                assert!(
                    status != 0 && status != outcome_unknown,
                    "status={status}, traffic={:?}, events={:?}, unresolved={:?}, intents={:?}, completions={:?}",
                    server.counted.traffic(),
                    event_snapshot,
                    unresolved_snapshot,
                    journal.intents.lock().unwrap(),
                    completion_snapshot
                );
                let mut observed = events.lock().unwrap().clone();
                observed.sort_by_key(|(id, _)| *id);
                let lost = observed
                    .iter()
                    .find(|(id, _)| *id == 1)
                    .map(|(_, code)| *code)
                    .expect("item 1 reports its own failure");
                // NotConnected (FFI code 29): the transport's lost-answer error reaches the
                // storage layer as a plain connectivity failure, never as OutcomeUnknown.
                let not_connected = 29;
                assert_eq!(
                    lost, not_connected,
                    "the lost Copy answer must fail item 1 as a plain failure: {observed:?}"
                );
                if !mixed_batch {
                    assert_eq!(status, not_connected);
                }
                if mixed_batch {
                    assert_eq!(
                        observed,
                        vec![
                            (1, lost),
                            (
                                2,
                                lore_revision::interface::LoreError::InvalidArguments as i32
                            ),
                            (3, 0),
                        ]
                    );
                } else {
                    assert_eq!(observed, vec![(1, lost)]);
                }
                // The Copy may have applied, so no payload Put follows it.
                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 0,
                        empty_puts: 0,
                        copies: 1
                    }
                );
                assert!(journal.unresolved().await?.is_empty());
                assert!(
                    journal.intents.lock().unwrap().is_empty(),
                    "a managed Copy must journal nothing"
                );
                let detail: serde_json::Value = {
                    let completed = completions.lock().unwrap();
                    assert_eq!(completed.len(), 1);
                    serde_json::from_str(&completed[0]).unwrap()
                };
                assert_ne!(detail["status"], outcome_unknown);
                assert!(
                    detail["error"]["attemptId"].is_null()
                        || detail["error"]["attemptId"] == "",
                    "no journaled attempt to name: {detail}"
                );
                close_handle(handle).await;
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn concurrent_managed_same_content_writes_keep_both_parents_without_tracker() -> TestResult
    {
        concurrent_managed_writes(false).await
    }

    #[tokio::test]
    async fn concurrent_managed_same_content_writes_keep_both_parents_with_tracker() -> TestResult {
        concurrent_managed_writes(true).await
    }

    #[tokio::test]
    async fn selected_namespace_matches_the_endpoint_used_by_the_actual_managed_write() -> TestResult
    {
        LORE_CONTEXT
            .scope(
                setup_execution("managed-endpoint-agreement".into()),
                async move {
                    let server = start_server().await;
                    let partition = Partition::from(*uuid::Uuid::now_v7().as_bytes());
                    let connection = lore_transport::connect(
                        &server.url,
                        "fixture-user",
                        partition,
                        4,
                        "",
                        FIXTURE_TOKEN,
                        lore_transport::auth::AuthMode::Auto,
                        None,
                    )
                    .await?;
                    let selected =
                        lore_transport::selected_caller_namespace(&connection, partition).await?;
                    assert_eq!(server.counted.traffic(), Traffic::default());
                    let session = connection.session(partition, "endpoint-agreement").await?;
                    let local = lore_storage::local::immutable_store::create(
                        None::<&str>,
                        ImmutableStoreCreateOptions::none(),
                        false,
                        ImmutableStoreSettings::default(),
                    )
                    .await?;
                    let journal = Arc::new(ManagedJournal::default());
                    // A fragment Put, Copy and PutResolved write no journal child, so the namespace
                    // a managed write binds is read off the still-journaled mutable store that
                    // follows the upload and the copy.
                    lore_transport::with_caller_operation(
                        lore_transport::CallerOperationContext::new(
                            uuid::Uuid::now_v7(),
                            partition,
                            journal.clone(),
                        ),
                        async {
                            let written = lore_storage::write::write_content(
                                local,
                                partition,
                                Context::from([0x98; 16]),
                                Bytes::from_static(b"real managed write namespace"),
                                lore_storage::options::WriteOptions::default(),
                                Some(session.clone()),
                                lore_storage::write_tracker::WriteContext::none(),
                                None,
                            )
                            .await?;
                            assert!(
                                journal.intents.lock().unwrap().is_empty(),
                                "a managed fragment Put must journal nothing"
                            );
                            session
                                .copy(partition, written.address, Context::from([0x97; 16]))
                                .await?;
                            assert!(
                                journal.intents.lock().unwrap().is_empty(),
                                "a managed Copy must journal nothing"
                            );
                            session
                                .mutable_store(
                                    lore_base::types::Hash::from([0x96; 32]),
                                    lore_base::types::Hash::from([0x95; 32]),
                                    lore_base::types::KeyType::Untyped,
                                )
                                .await?;
                            TestResult::Ok(())
                        },
                    )
                    .await?;
                    assert_eq!(server.counted.traffic().payload_puts, 1);
                    assert_eq!(server.counted.traffic().copies, 1);
                    assert!(journal.unresolved().await?.is_empty());
                    let intents = journal.intents.lock().unwrap();
                    assert_eq!(intents.len(), 1);
                    let actual = intents.values().next().unwrap();
                    assert_eq!(actual.rpc, "StorageService.MutableStore");
                    assert_eq!(actual.endpoint, selected.endpoint);
                    assert_eq!(actual.repository, selected.repository);
                    assert_eq!(actual.verified_issuer, selected.verified_issuer);
                    assert_eq!(actual.authenticated_subject, selected.authenticated_subject);
                    assert_eq!(actual.caller_capabilities, selected.caller_capabilities);
                    Ok(())
                },
            )
            .await
    }

    async fn concurrent_managed_writes(with_tracker: bool) -> TestResult {
        LORE_CONTEXT
            .scope(
                setup_execution("concurrent-managed-uploads".into()),
                async move {
                    let server = start_server().await;
                    let partition = Partition::from(*uuid::Uuid::now_v7().as_bytes());
                    let connection = lore_transport::connect(
                        &server.url,
                        "fixture-user",
                        partition,
                        4,
                        "",
                        FIXTURE_TOKEN,
                        lore_transport::auth::AuthMode::Auto,
                        None,
                    )
                    .await?;
                    let session = connection
                        .session(partition, "concurrent-managed-uploads")
                        .await?;
                    let selected =
                        lore_transport::selected_caller_namespace(&connection, partition).await?;
                    assert_eq!(selected.repository, partition);
                    assert_eq!(selected.verified_issuer, "https://fixture.invalid/issuer");
                    assert_eq!(selected.authenticated_subject, "fixture-user");
                    assert_eq!(selected.caller_capabilities, "outcome_unknown_v1");
                    assert_eq!(
                        server.counted.traffic(),
                        Traffic::default(),
                        "namespace selection must issue no storage write"
                    );
                    let local = lore_storage::local::immutable_store::create(
                        None::<&str>,
                        ImmutableStoreCreateOptions::none(),
                        false,
                        ImmutableStoreSettings::default(),
                    )
                    .await?;
                    // Neither response can complete until BOTH separate requests reached the store.
                    // A shared leader/follower shortcut leaves one arrival and times out.
                    *server.counted.put_barrier.lock().unwrap() =
                        Some(Arc::new(tokio::sync::Barrier::new(2)));
                    server
                        .counted
                        .lose_put_response
                        .store(true, Ordering::SeqCst);
                    let journals = [
                        Arc::new(ManagedJournal::default()),
                        Arc::new(ManagedJournal::default()),
                    ];
                    let parents = [uuid::Uuid::now_v7(), uuid::Uuid::now_v7()];
                    let tracker = with_tracker
                        .then(|| Arc::new(lore_storage::write_tracker::WriteTracker::new()));
                    let upload = |index: usize| {
                        lore_transport::caller_operation::with_caller_operation(
                            lore_transport::caller_operation::CallerOperationContext::new(
                                parents[index],
                                partition,
                                journals[index].clone(),
                            ),
                            lore_storage::write::write_content(
                                local.clone(),
                                partition,
                                Context::from([0x99; 16]),
                                Bytes::from_static(
                                    b"same bytes and address under distinct managed parents",
                                ),
                                lore_storage::options::WriteOptions::default(),
                                Some(session.clone()),
                                lore_storage::write_tracker::WriteContext::tracked(
                                    tracker.clone(),
                                    None,
                                ),
                                None,
                            ),
                        )
                    };
                    let (first, second) = tokio::time::timeout(Duration::from_secs(10), async {
                        tokio::join!(upload(0), upload(1))
                    })
                    .await
                    .expect("both managed parents must independently reach the wire");
                    // A lost Put answer is a retryable internal failure, never an unknown outcome
                    // and never a journal child; the error names the wire attempt id.
                    let mut ids = Vec::new();
                    for result in [first, second] {
                        let error = result.err().expect("the lost answer must fail the write");
                        let text = error.to_string();
                        assert!(
                            !error.is_outcome_unknown() && text.contains("lost its answer"),
                            "error={error:?}, traffic={:?}",
                            server.counted.traffic()
                        );
                        let attempt = text
                            .split("StorageService.Put attempt ")
                            .nth(1)
                            .and_then(|rest| rest.split(' ').next())
                            .unwrap_or_else(|| panic!("no attempt id in {text}"))
                            .to_owned();
                        ids.push(attempt);
                    }
                    assert_eq!(
                        server.counted.traffic(),
                        Traffic {
                            payload_puts: 2,
                            empty_puts: 0,
                            copies: 0
                        }
                    );
                    for journal in &journals {
                        assert!(journal.unresolved().await?.is_empty());
                        assert!(
                            journal.intents.lock().unwrap().is_empty(),
                            "a managed fragment Put must journal nothing"
                        );
                    }
                    assert_ne!(
                        ids[0], ids[1],
                        "each parent's Put carries its own attempt id"
                    );
                    if let Some(tracker) = tracker {
                        tracker.await_all().await?;
                    }
                    Ok(())
                },
            )
            .await
    }

    /// Whether any link of `error`'s chain is a `ProtocolError` carrying the unjournaled
    /// lost-answer mark.
    fn chain_has_unjournaled_answer_lost(error: &(dyn Error + 'static)) -> bool {
        let mut current = Some(error);
        while let Some(link) = current {
            if link
                .downcast_ref::<lore_transport::ProtocolError>()
                .is_some_and(lore_transport::is_unjournaled_answer_lost)
            {
                return true;
            }
            current = link.source();
        }
        // PushError keeps the cause inside its own traced payload, not as a source() link, so
        // the typed mark is read off the rendering of that payload.
        format!("{error:?}").contains("UnjournaledAnswerLost {")
    }

    /// A real `push_fragments` with one copyable fragment (the peer holds the hash under another
    /// context, the local store holds the payload) against the counting server, as a managed
    /// operation. Returns the push result, the journal, and the peer's traffic.
    async fn push_one_copyable_fragment(
        server: &TestServer,
    ) -> (
        Result<(), lore_revision::branch::push::PushError>,
        Arc<ManagedJournal>,
    ) {
        let handle = open_handle_with_token(server, FIXTURE_TOKEN).await;
        let payload = b"copyable: the peer holds this hash under another context".to_vec();
        let partition = Partition::from(*uuid::Uuid::now_v7().as_bytes());
        let first = put_with_token(
            handle,
            partition,
            Context::from([0x82; 16]),
            &payload,
            1,
            0,
            FIXTURE_TOKEN,
        )
        .await;
        close_handle(handle).await;
        server.counted.reset();

        let address = Address {
            hash: first.hash,
            context: Context::from([0x83; 16]),
        };
        let immutable = lore_storage::local::immutable_store::create(
            None::<&str>,
            ImmutableStoreCreateOptions::none(),
            false,
            ImmutableStoreSettings::default(),
        )
        .await
        .unwrap();
        let mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .unwrap();
        let mut context = lore_revision::repository::RepositoryContext::new_null_context(
            immutable,
            mutable,
            lore_revision::state::allow_all_repositories(),
        );
        context.id = partition;
        let repository = Arc::new(context);
        let size = u32::try_from(payload.len()).unwrap();
        repository
            .immutable_store()
            .put(
                repository.id,
                address,
                Fragment {
                    flags: 0,
                    size_payload: size,
                    size_content: u64::from(size),
                },
                Some(Bytes::from(payload)),
                false,
            )
            .await
            .unwrap();

        let connection = lore_transport::connect(
            &server.url,
            "fixture-user",
            repository.id,
            4,
            "",
            FIXTURE_TOKEN,
            lore_transport::auth::AuthMode::Auto,
            None,
        )
        .await
        .unwrap();
        let session = connection
            .session(repository.id, "push-copyable")
            .await
            .unwrap();
        let queried = lore_revision::branch::push::PushQueryResult {
            absent: Vec::new(),
            copyable: vec![address],
            present: Vec::new(),
        };
        let progress = Arc::new(lore_revision::branch::push::PushProgress::new(Arc::new(
            lore_revision::branch::push::PushStats::new(false),
        )));
        let journal = Arc::new(ManagedJournal::default());
        let result = lore_transport::with_caller_operation(
            lore_transport::CallerOperationContext::new(
                uuid::Uuid::now_v7(),
                repository.id,
                journal.clone(),
            ),
            lore_revision::branch::push::push_fragments(repository, session, queried, progress),
        )
        .await;
        (result, journal)
    }

    /// A lost managed Copy answer fails the push, and the push does not fall back to a Put for
    /// that address: the Copy may have applied, and an upload would be a second mutation.
    #[tokio::test]
    async fn a_push_whose_copy_answer_is_lost_fails_and_sends_no_fallback_put() -> TestResult {
        LORE_CONTEXT
            .scope(setup_execution("push-copy-lost".into()), async move {
                let server = start_server().await;
                // The Copy applies on the peer and its answer is lost.
                server
                    .counted
                    .lose_copy_response
                    .store(true, Ordering::SeqCst);
                let (result, journal) = push_one_copyable_fragment(&server).await;
                let error = result.expect_err("a lost Copy answer must fail the push");
                assert!(!error.is_outcome_unknown(), "{error:?}");
                assert!(
                    error.to_string().contains("lost its answer")
                        || format!("{error:?}").contains("lost its answer"),
                    "{error:?}"
                );
                assert!(
                    chain_has_unjournaled_answer_lost(&error),
                    "the error chain must carry the lost-answer mark: {error:?}"
                );
                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 0,
                        empty_puts: 0,
                        copies: 1
                    },
                    "one Copy, and no fallback Put"
                );
                assert!(journal.unresolved().await?.is_empty());
                assert!(journal.intents.lock().unwrap().is_empty());
                Ok(())
            })
            .await
    }

    /// A decisive Copy refusal still falls back to uploading the payload.
    #[tokio::test]
    async fn a_push_whose_copy_is_refused_still_falls_back_to_a_put() -> TestResult {
        LORE_CONTEXT
            .scope(setup_execution("push-copy-refused".into()), async move {
                let server = start_refusing_server().await;
                let (result, journal) = push_one_copyable_fragment(&server).await;
                result.expect("a decisive refusal falls back to an upload");
                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 1,
                        empty_puts: 0,
                        copies: 1
                    }
                );
                assert!(journal.unresolved().await?.is_empty());
                assert!(journal.intents.lock().unwrap().is_empty());
                Ok(())
            })
            .await
    }

    struct TestServer {
        url: String,
        counted: Arc<CountingStore>,
        _stop: TestServerStop,
    }

    async fn start_server() -> TestServer {
        start_server_with(CountingStore::new).await
    }

    async fn start_refusing_server() -> TestServer {
        start_server_with(CountingStore::refusing_copy).await
    }

    async fn start_server_with(
        wrap: impl FnOnce(Arc<dyn ImmutableStore>) -> Arc<CountingStore>,
    ) -> TestServer {
        // Isolated, as Lore Server's store is: isolation decides what the client is told about
        // content it did not store itself.
        let (backend, mutable) = make_backends(Partitions::Isolated).await;
        let counted = wrap(backend);
        let (url, stop) = start_grpc_server(counted.clone(), mutable);

        TestServer {
            url,
            counted,
            _stop: stop,
        }
    }

    /// FORK-LOCAL (Tideshift): a storage handle bound to `server` whose calls carry `token`.
    /// Auth-off discovery cannot infer an identity from a supplied token, so the fixture
    /// identity is bound explicitly for the lazy connection to use that token.
    async fn open_handle_with_token(server: &TestServer, token: &str) -> LoreStore {
        open_handle_with_globals(
            LoreGlobalArgs {
                access_token: LoreString::from(token),
                identity: LoreString::from(if token.is_empty() { "" } else { "fixture-user" }),
                ..Default::default()
            },
            Some(&server.url),
        )
        .await
    }

    /// FORK-LOCAL (Tideshift): one `lore_storage_put` carrying `token`, returning the address it
    /// produced.
    async fn put_with_token(
        handle: LoreStore,
        partition: Partition,
        context: Context,
        bytes: &[u8],
        remote_write: u8,
        chunk: u64,
        token: &str,
    ) -> Address {
        let captured: Arc<Mutex<Vec<(Address, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = captured.clone();
        let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
            if let LoreEvent::StoragePutItemComplete(data) = event {
                sink.lock()
                    .unwrap()
                    .push((data.address, data.error.error_code));
            }
        }));
        let status = lore::storage::put::put(
            LoreGlobalArgs {
                access_token: LoreString::from(token),
                ..Default::default()
            },
            lore::storage::put::LoreStoragePutArgs {
                handle,
                items: LoreArray::from_vec(vec![lore::storage::put::LoreStoragePutItem {
                    id: 1,
                    partition,
                    context,
                    data: LoreBytes {
                        ptr: bytes.as_ptr().cast(),
                        len: bytes.len(),
                    },
                    remote_write,
                    local_cache: 0,
                    fixed_size_chunk: chunk,
                    remote_query: 0,
                }]),
            },
            callback,
        )
        .await;
        assert_eq!(status, 0, "put must succeed");
        let events = captured.lock().unwrap().clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, 0);
        events[0].0
    }

    async fn put_remote(
        handle: LoreStore,
        partition: Partition,
        context: Context,
        bytes: &[u8],
    ) -> Address {
        put_content(handle, partition, context, bytes, 1, 0).await
    }

    async fn put_local_only(
        handle: LoreStore,
        partition: Partition,
        context: Context,
        bytes: &[u8],
    ) -> Address {
        put_content(handle, partition, context, bytes, 0, 0).await
    }

    async fn assert_peer_holds(
        server: &TestServer,
        partition: Partition,
        address: Address,
        payload: &[u8],
    ) {
        let store: Arc<dyn ImmutableStore> = server.counted.clone();
        let resolved = query_one(&store, partition, address)
            .await
            .expect("query the peer");
        assert_eq!(
            resolved.match_made,
            StoreMatch::MatchFull,
            "the peer must hold the association the write registered"
        );

        let (_fragment, bytes) = lore_storage::read::read(
            store,
            partition,
            address,
            None,
            lore_storage::options::ReadOptions::default(),
            None,
        )
        .await
        .expect("read the address back from the peer");
        assert_eq!(
            bytes.as_ref(),
            payload,
            "the copied association must serve the original bytes"
        );
    }

    /// The flagship case: the same bytes written again under a different context in the same
    /// partition. The peer holds the payload already, so it is asked for an association.
    #[tokio::test]
    async fn a_second_context_in_the_same_partition_copies_instead_of_uploading() -> TestResult {
        let execution = setup_execution("copy-on-write-same-partition".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_server().await;
                let handle = open_handle(Some(&server.url)).await;

                let partition = Partition::from([0x11u8; 16]);
                let first_context = Context::from([0x12u8; 16]);
                let second_context = Context::from([0x13u8; 16]);
                let payload = b"one payload, two files that happen to be identical".to_vec();

                let first = put_remote(handle, partition, first_context, &payload).await;
                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 1,
                        empty_puts: 0,
                        copies: 0
                    },
                    "content the peer has never seen has to be uploaded"
                );

                server.counted.reset();
                let second = put_remote(handle, partition, second_context, &payload).await;

                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 0,
                        empty_puts: 0,
                        copies: 1
                    },
                    "the peer already holds these bytes, so it must be asked for an association"
                );
                assert_eq!(first.hash, second.hash);
                assert_eq!(second.context, second_context);

                assert_eq!(
                    server.counted.copy_sources(),
                    vec![(
                        partition,
                        Address {
                            hash: first.hash,
                            context: first_context
                        }
                    )],
                    "the source named is the association the client knows the peer holds"
                );

                assert_peer_holds(&server, partition, second, &payload).await;
                assert_peer_holds(&server, partition, first, &payload).await;

                close_handle(handle).await;
                Ok(())
            })
            .await
    }

    /// The same bytes written into a second partition. The source is one the client has a claim to,
    /// so the association can be duplicated across the boundary rather than uploaded again.
    #[tokio::test]
    async fn a_second_partition_copies_from_the_first() -> TestResult {
        let execution = setup_execution("copy-on-write-cross-partition".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_server().await;
                let handle = open_handle(Some(&server.url)).await;

                let source_partition = Partition::from([0x21u8; 16]);
                let target_partition = Partition::from([0x22u8; 16]);
                let context = Context::from([0x23u8; 16]);
                let payload = b"shared store, two repositories, one payload".to_vec();

                let first = put_remote(handle, source_partition, context, &payload).await;
                server.counted.reset();

                let second = put_remote(handle, target_partition, context, &payload).await;

                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 0,
                        empty_puts: 0,
                        copies: 1
                    },
                    "a partition the caller can reach is a source, not a reason to re-upload"
                );
                assert_eq!(
                    server.counted.copy_sources(),
                    vec![(
                        source_partition,
                        Address {
                            hash: first.hash,
                            context
                        }
                    )],
                    "the copy must name the partition the client found the content in"
                );

                assert_peer_holds(&server, target_partition, second, &payload).await;
                assert_peer_holds(&server, source_partition, first, &payload).await;

                close_handle(handle).await;
                Ok(())
            })
            .await
    }

    /// A local association the peer never received names no source it could copy from. Skipping the
    /// upload on the strength of it would leave the address registered nowhere.
    #[tokio::test]
    async fn a_source_the_peer_never_received_is_uploaded() -> TestResult {
        let execution = setup_execution("copy-on-write-not-durable".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_server().await;
                let handle = open_handle(Some(&server.url)).await;

                let partition = Partition::from([0x31u8; 16]);
                let payload = b"stored locally, never pushed".to_vec();

                put_local_only(handle, partition, Context::from([0x32u8; 16]), &payload).await;
                assert_eq!(
                    server.counted.traffic(),
                    Traffic::default(),
                    "a local-only write must not touch the peer at all"
                );

                let second =
                    put_remote(handle, partition, Context::from([0x33u8; 16]), &payload).await;

                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 1,
                        empty_puts: 0,
                        copies: 0
                    },
                    "the peer holds nothing to copy from, so the payload has to be transferred"
                );
                assert_peer_holds(&server, partition, second, &payload).await;

                close_handle(handle).await;
                Ok(())
            })
            .await
    }

    /// A copy is an attempt, not a commitment. A peer that refuses one leaves the write to upload
    /// exactly as it would have without ever trying.
    #[tokio::test]
    async fn a_refused_copy_falls_back_to_uploading() -> TestResult {
        let execution = setup_execution("copy-on-write-refused".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_refusing_server().await;
                let handle = open_handle(Some(&server.url)).await;

                let partition = Partition::from([0x41u8; 16]);
                let payload = b"the peer will not answer a copy for this".to_vec();

                put_remote(handle, partition, Context::from([0x42u8; 16]), &payload).await;
                server.counted.reset();

                let second =
                    put_remote(handle, partition, Context::from([0x43u8; 16]), &payload).await;

                assert_eq!(
                    server.counted.traffic(),
                    Traffic {
                        payload_puts: 1,
                        empty_puts: 0,
                        copies: 1
                    },
                    "the refused copy must be followed by the upload it was standing in for"
                );
                assert_peer_holds(&server, partition, second, &payload).await;

                close_handle(handle).await;
                Ok(())
            })
            .await
    }

    /// An address the peer already holds outright is a full match, which needs neither verb.
    #[tokio::test]
    async fn re_writing_the_same_address_asks_the_peer_for_nothing() -> TestResult {
        let execution = setup_execution("copy-on-write-full-match".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_server().await;
                let handle = open_handle(Some(&server.url)).await;

                let partition = Partition::from([0x51u8; 16]);
                let context = Context::from([0x52u8; 16]);
                let payload = b"written once, written again identically".to_vec();

                put_remote(handle, partition, context, &payload).await;
                server.counted.reset();

                put_remote(handle, partition, context, &payload).await;

                assert_eq!(
                    server.counted.traffic(),
                    Traffic::default(),
                    "the association already exists, so there is nothing to send or duplicate"
                );

                close_handle(handle).await;
                Ok(())
            })
            .await
    }

    /// Content cut into a fragment tree makes the choice per fragment. Every leaf and every list
    /// block is content-addressed, so a second context copies the whole tree.
    #[tokio::test]
    async fn every_fragment_of_a_tree_copies_rather_than_uploads() -> TestResult {
        let execution = setup_execution("copy-on-write-fragmented".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_server().await;
                let handle = open_handle(Some(&server.url)).await;

                let partition = Partition::from([0x61u8; 16]);
                let chunk = 64 * 1024u64;
                // Deterministic and non-repeating, so the fragments differ from one another.
                let payload: Vec<u8> = (0..(chunk as usize * 6 + 977))
                    .map(|index| (index.wrapping_mul(2_654_435_761) >> 11) as u8)
                    .collect();

                let first = put_content(
                    handle,
                    partition,
                    Context::from([0x62u8; 16]),
                    &payload,
                    1,
                    chunk,
                )
                .await;
                let uploaded = server.counted.traffic();
                assert!(
                    uploaded.payload_puts > 6,
                    "the test wants a real tree, got {uploaded:?}"
                );

                server.counted.reset();
                let second = put_content(
                    handle,
                    partition,
                    Context::from([0x63u8; 16]),
                    &payload,
                    1,
                    chunk,
                )
                .await;
                let duplicated = server.counted.traffic();

                assert_eq!(
                    duplicated.payload_puts, 0,
                    "no fragment of an identical tree needs its payload transferred again"
                );
                assert_eq!(
                    duplicated.copies, uploaded.payload_puts,
                    "every fragment the first write uploaded is one the second duplicates"
                );
                assert_eq!(first.hash, second.hash);

                assert_peer_holds(&server, partition, second, &payload).await;

                close_handle(handle).await;
                Ok(())
            })
            .await
    }

    /// The source a copy names is the exact association the client's own store recorded, which is
    /// what lets a peer confirm it with a keyed read instead of searching the partition.
    #[tokio::test]
    async fn the_copy_names_the_exact_association_the_client_knows_about() -> TestResult {
        let execution = setup_execution("copy-on-write-exact-source".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let server = start_server().await;
                let handle = open_handle(Some(&server.url)).await;

                let partition = Partition::from([0x71u8; 16]);
                let held = Context::from([0x72u8; 16]);
                let payload = b"the source is named, not searched for".to_vec();

                let first = put_remote(handle, partition, held, &payload).await;
                server.counted.reset();

                put_remote(handle, partition, Context::from([0x73u8; 16]), &payload).await;

                let sources = server.counted.copy_sources();
                assert_eq!(sources.len(), 1);
                assert_eq!(sources[0].0, partition);
                assert_eq!(sources[0].1.hash, first.hash);
                assert_eq!(
                    sources[0].1.context, held,
                    "an unnamed context would make the peer search the partition instead"
                );

                close_handle(handle).await;
                Ok(())
            })
            .await
    }
}
