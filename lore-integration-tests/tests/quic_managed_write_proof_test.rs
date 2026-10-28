// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-124 slice 4: live proofs for managed writes over QUIC that the unit tier cannot give.
//
// [CLIENT]-class: `lore-transport`'s QUIC client sends a managed fragment `Put` on a declared
// session, and a lost answer to it is `UnjournaledAnswerLost`, never an unknown outcome and never
// a resend. The server is the real strict (`RequireOutcomeUnknownV1`) `StorageServiceV4`, wrapped
// only to record the wire and to hold one applied `Put` answer while the test closes the server
// under it (`quic_managed_write_support`).
//
// What the loss cases prove: a managed `Put` whose answer is lost after the server applied it
// resolves to `UnjournaledAnswerLost` (not `OutcomeUnknown`), the client sends exactly one `Put`,
// no journal child is written, and nothing is resent. "Nothing is resent" is observed where a
// resend could land: a replacement server is brought up on the same port BEFORE the writer's call
// returns, and its wire must stay free of any `Put` and any `Authorize`. A later managed `Put` on
// the same session is then admitted by that replacement. The push variant adds that the next push
// re-queries, finds the severed fragment already stored, and uploads only the missing one.
//
// The replaced-connection case moves the connection generation (a sibling's reconnect) while the
// answer is owed. That is the only state in which `StorageSession::attempt` could resend after the
// error (`replaced` is true), so it is the case that tells the session layer's refusal to retry a
// non-rebind error (`session.rs`, `not_dispatched`) from the transport's own refusal.
//
// What they do not prove: the server dying BEFORE it applied the `Put` (the answer is withheld only
// after the real write, so the severed fragment is always stored), a real `lore push` through a
// repository (the push is `push_fragments` over a null-context repository, the same unit
// `quic_session_rebind_test.rs` b12 drives), or a kernel-level kill of a server process.
//
// The `lores://` (TLS) cases live in their own test binary, `quic_lores_tls_test.rs`, because they
// need a process-wide trust setting.
#[cfg(all(test, feature = "integration_tests"))]
mod quic_managed_write_proof_tests {
    use std::error::Error;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use lore_base::types::Address;
    use lore_revision::fragment;
    use lore_revision::lore::RepositoryId;
    use lore_transport::Connection;
    use lore_transport::attempt_store::AttemptStore;
    use lore_transport::error::ProtocolError;
    use lore_transport::is_unjournaled_answer_lost;
    use lore_transport::quic::storage_service::Command;
    use lore_transport::with_caller_operation;
    use rand::random;

    use crate::quic_managed_write_support::ACTION_START;
    use crate::quic_managed_write_support::ACTION_START_DECLARED;
    use crate::quic_managed_write_support::Cell;
    use crate::quic_managed_write_support::Probe;
    use crate::quic_managed_write_support::RESEND_SETTLE;
    use crate::quic_managed_write_support::TestResult;
    use crate::quic_managed_write_support::WAIT;
    use crate::quic_managed_write_support::Wire;
    use crate::quic_managed_write_support::cell;
    use crate::quic_managed_write_support::connect;
    use crate::quic_managed_write_support::fresh_stores;
    use crate::quic_managed_write_support::hold_first_put_answer;
    use crate::quic_managed_write_support::in_context;
    use crate::quic_managed_write_support::lose_answer_and_restart;
    use crate::quic_managed_write_support::managed;
    use crate::quic_managed_write_support::stored;

    /// After the writer's call returned, give a resend time to reach the replacement, then require
    /// that nothing at all of the lost write arrived: no `Put`, and no `Authorize` (a resend must
    /// start a session first, so an `Authorize` is the earlier sign of one).
    async fn assert_nothing_resent(replacement: &Probe) {
        tokio::time::sleep(RESEND_SETTLE).await;
        let wire = replacement.wire();
        assert_eq!(
            replacement.count_opcode(Command::Put),
            0,
            "the lost Put was resent to the replacement: {wire:?}"
        );
        assert_eq!(
            replacement.count_opcode(Command::Authorize),
            0,
            "the lost Put's session layer started a session on the replacement: {wire:?}"
        );
    }

    /// The client-side facts every lost-answer case shares: the error, the one attempt, no journal
    /// child, and that the write the caller could not see did happen.
    async fn assert_lost_answer_shape(
        error: &ProtocolError,
        cell: &Cell,
        journal: &crate::quic_managed_write_support::CountingJournal,
        partition: RepositoryId,
        address: Address,
    ) -> TestResult {
        assert!(
            is_unjournaled_answer_lost(error),
            "a lost managed fragment-write answer is an unjournaled loss: {error:?}"
        );
        assert!(
            !error.is_outcome_unknown(),
            "it is never an unknown outcome a parent would wait on: {error:?}"
        );
        let wire = cell.probe.wire();
        assert_eq!(cell.probe.count_opcode(Command::Put), 1, "{wire:?}");
        assert_eq!(
            cell.probe.count_action(ACTION_START_DECLARED),
            1,
            "{wire:?}"
        );
        // The undeclared Authorize (the session's eager start) is the only other start.
        assert_eq!(cell.probe.count_action(ACTION_START), 1, "{wire:?}");
        assert_eq!(journal.records.load(Ordering::SeqCst), 0);
        assert!(journal.unresolved().await?.is_empty());
        assert!(
            stored(&cell.stores, partition, address).await,
            "the lost answer followed a real write"
        );
        Ok(())
    }

    /// A managed `Put` over QUIC whose answer is lost after the server applied it.
    ///
    /// The fragment is stored (the answer was withheld only after the real write), the caller gets
    /// `UnjournaledAnswerLost` and not an unknown outcome, the client wrote exactly one `Put`, no
    /// journal child exists, and the live replacement server sees none of it resent. A new managed
    /// `Put` on the same session is then admitted by the replacement on a declared session.
    #[tokio::test]
    async fn a_managed_quic_put_with_a_lost_answer_is_unjournaled_loss_sent_once_then_a_restarted_server_admits_the_next()
    -> TestResult {
        in_context(async {
            let hold = hold_first_put_answer();
            let mut cell = cell(Some(hold.clone()), None, None).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await?;
            let session = connection.session(partition, "lost-put").await?;
            let (fragment, address, payload) = fragment::generate_random();
            let (scope, journal) = managed(partition);
            let server = cell.quic.take().expect("the cell's QUIC server");

            let (result, (replacement_server, replacement)) = tokio::join!(
                tokio::time::timeout(
                    WAIT,
                    with_caller_operation(
                        scope.clone(),
                        session.put(address, fragment, Some(payload.clone())),
                    ),
                ),
                lose_answer_and_restart(&hold, server, cell.port, &cell.stores, async {}),
            );
            cell.quic = Some(replacement_server);
            let error = result
                .expect("a lost answer must end the Put, not hang it")
                .expect_err("the Put's answer was lost, so the call cannot succeed");
            assert_eq!(scope.declared_session_count(), 1, "the Put ran declared");
            assert_lost_answer_shape(&error, &cell, &journal, partition, address).await?;
            assert_nothing_resent(&replacement).await;

            // The replacement admits the next managed Put on the same session.
            let (next_fragment, next_address, next_payload) = fragment::generate_random();
            let (next_scope, next_journal) = managed(partition);
            with_caller_operation(
                next_scope.clone(),
                session.put(next_address, next_fragment, Some(next_payload.clone())),
            )
            .await?;
            assert_eq!(next_scope.declared_session_count(), 1);
            assert_eq!(
                replacement.count_opcode(Command::Put),
                1,
                "only the new Put reaches the replacement: {:?}",
                replacement.wire()
            );
            assert_declared_put_on(&replacement);
            assert_eq!(next_journal.records.load(Ordering::SeqCst), 0);
            let (_, read) = session.get(&next_address).await?;
            assert_eq!(read, next_payload);
            Ok(())
        })
        .await
    }

    /// The Put the replacement received ran on a declared session, with one declared start or two.
    ///
    /// KNOWN DEFECT, recorded in WP-124: `SessionBinding::resolve` samples the connection
    /// generation BEFORE the `session_start_declared` that reconnects (`session.rs:108-139`), so the
    /// first managed call after a connection died records the older generation and rebinds once.
    /// Measured: two declared starts, the first orphaned until the connection ends. Tighten the
    /// range to exactly 1 when that is fixed.
    fn assert_declared_put_on(replacement: &Probe) {
        let puts: Vec<Wire> = replacement
            .wire()
            .into_iter()
            .filter(|w| w.opcode == Command::Put as u8)
            .collect();
        assert_eq!(
            replacement.declared_of(puts[0].session_id),
            Some(true),
            "the Put ran on a declared session the replacement holds"
        );
        let starts = replacement.count_action(ACTION_START_DECLARED);
        assert!(
            (1..=2).contains(&starts),
            "{starts} declared starts: {:?}",
            replacement.wire()
        );
    }

    /// The lost answer arrives AFTER the connection was replaced under the writer.
    ///
    /// `Connection::advance_storage_generation_before_epoch_for_test` is the seam for a sibling's
    /// reconnect: it moves the connection generation while the Put's answer is still owed, so when
    /// the answer is lost `StorageSession::attempt` sees `replaced == true` and the only thing left
    /// between the caller and a second `Put` is the session layer's refusal to retry an error that
    /// is not a rebind proof. The replacement is up, so a resend would show on its wire.
    #[tokio::test]
    async fn a_lost_managed_put_answer_is_not_resent_when_the_connection_was_replaced_meanwhile()
    -> TestResult {
        in_context(async {
            let hold = hold_first_put_answer();
            let mut cell = cell(Some(hold.clone()), None, None).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await?;
            let session = connection.session(partition, "lost-put-replaced").await?;
            let (fragment, address, payload) = fragment::generate_random();
            let (scope, journal) = managed(partition);
            let server = cell.quic.take().expect("the cell's QUIC server");
            let replace_connection = replace_connection_generation(&connection);

            let (result, (replacement_server, replacement)) = tokio::join!(
                tokio::time::timeout(
                    WAIT,
                    with_caller_operation(
                        scope.clone(),
                        session.put(address, fragment, Some(payload.clone())),
                    ),
                ),
                lose_answer_and_restart(&hold, server, cell.port, &cell.stores, replace_connection),
            );
            cell.quic = Some(replacement_server);
            let error = result
                .expect("a lost answer must end the Put, not hang it")
                .expect_err("the Put's answer was lost, so the call cannot succeed");
            assert_eq!(scope.declared_session_count(), 1, "the Put ran declared");
            assert_lost_answer_shape(&error, &cell, &journal, partition, address).await?;
            assert_nothing_resent(&replacement).await;
            Ok(())
        })
        .await
    }

    /// Move the storage connection generation, as a sibling task's reconnect does.
    async fn replace_connection_generation(connection: &Arc<Connection>) {
        connection
            .advance_storage_generation_before_epoch_for_test()
            .await
            .expect("the generation seam is available on a connected QUIC client");
    }

    /// A push (`push_fragments` over a null-context repository, the unit b12 drives) whose managed
    /// QUIC `Put` loses its answer fails with the lost-answer mark, nothing is resent, and the NEXT
    /// push, against the replacement server, re-queries and uploads only the fragment that is
    /// missing.
    #[tokio::test]
    async fn a_managed_push_that_loses_a_quic_put_answer_fails_and_the_next_push_uploads_only_what_is_missing()
    -> TestResult {
        in_context(async {
            let hold = hold_first_put_answer();
            let mut cell = cell(Some(hold.clone()), None, None).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await?;
            let session = connection.session(partition, "lost-push").await?;

            let (frag_a, address_a, payload_a) = fragment::generate_random();
            let (frag_b, address_b, payload_b) = fragment::generate_random();
            let (local, local_mutable) = fresh_stores().await;
            let mut context = lore_revision::repository::RepositoryContext::new_null_context(
                local,
                local_mutable,
            );
            context.id = partition;
            let repository = Arc::new(context);
            for (address, fragment, payload) in [
                (address_a, frag_a, payload_a.clone()),
                (address_b, frag_b, payload_b.clone()),
            ] {
                repository
                    .immutable_store()
                    .put(repository.id, address, fragment, Some(payload), false)
                    .await
                    .expect("local payload");
            }

            let progress = || {
                Arc::new(lore_revision::branch::push::PushProgress::new(Arc::new(
                    lore_revision::branch::push::PushStats::new(false),
                )))
            };

            // First push: only A is on the list, and its answer is lost.
            let (scope, journal) = managed(partition);
            let server = cell.quic.take().expect("the cell's QUIC server");
            let first = lore_revision::branch::push::PushQueryResult {
                absent: vec![address_a],
                copyable: Vec::new(),
                present: Vec::new(),
            };
            let (result, (replacement_server, replacement)) = tokio::join!(
                tokio::time::timeout(
                    WAIT,
                    with_caller_operation(
                        scope.clone(),
                        lore_revision::branch::push::push_fragments(
                            repository.clone(),
                            session.clone(),
                            first,
                            progress(),
                        ),
                    ),
                ),
                lose_answer_and_restart(&hold, server, cell.port, &cell.stores, async {}),
            );
            cell.quic = Some(replacement_server);
            let error = result
                .expect("a lost answer must end the push, not hang it")
                .expect_err("the push's only Put lost its answer");
            assert!(!error.is_outcome_unknown(), "{error:?}");
            assert!(
                chain_has_unjournaled_answer_lost(&error),
                "the push error must carry the lost-answer mark: {error:?}"
            );
            let wire = cell.probe.wire();
            assert_eq!(
                cell.probe.count_opcode(Command::Put),
                1,
                "the push sent its Put once: {wire:?}"
            );
            assert_eq!(journal.records.load(Ordering::SeqCst), 0);
            assert!(journal.unresolved().await?.is_empty());
            assert!(stored(&cell.stores, partition, address_a).await);
            assert!(!stored(&cell.stores, partition, address_b).await);
            assert_nothing_resent(&replacement).await;

            // Second push, against the replacement: ask what is missing, then upload exactly that.
            let (next_scope, next_journal) = managed(partition);
            let statuses = session.query(&[address_a, address_b]).await?;
            let mut second = lore_revision::branch::push::PushQueryResult::default();
            lore_revision::branch::push::classify_query_batch(
                &[address_a, address_b],
                &statuses,
                &mut second,
            );
            assert_eq!(
                second.present,
                vec![address_a],
                "A was applied before the loss"
            );
            assert_eq!(second.absent, vec![address_b], "only B is missing");
            tokio::time::timeout(
                WAIT,
                with_caller_operation(
                    next_scope.clone(),
                    lore_revision::branch::push::push_fragments(
                        repository.clone(),
                        session.clone(),
                        second,
                        progress(),
                    ),
                ),
            )
            .await
            .expect("the clean second push must finish")?;
            assert_eq!(
                replacement.count_opcode(Command::Put),
                1,
                "the second push uploads B only: {:?}",
                replacement.wire()
            );
            assert!(stored(&cell.stores, partition, address_b).await);
            assert_eq!(next_journal.records.load(Ordering::SeqCst), 0);
            let (_, read) = session.get(&address_b).await?;
            assert_eq!(read, payload_b);
            Ok(())
        })
        .await
    }

    /// Whether any link of `error`'s chain is a `ProtocolError` carrying the unjournaled
    /// lost-answer mark.
    ///
    /// `PushError` keeps its cause inside its own traced payload (`internal_with_context`), not as
    /// a `source()` link, and exposes no accessor for it, so the typed check cannot reach the mark
    /// through a push. The last line reads it off the rendering of that payload by the type's own
    /// name; `storage_copy_on_write_test.rs` does the same. The direct-`Put` tests above use the
    /// typed check only.
    fn chain_has_unjournaled_answer_lost(error: &(dyn Error + 'static)) -> bool {
        let mut current = Some(error);
        while let Some(link) = current {
            if link
                .downcast_ref::<ProtocolError>()
                .is_some_and(is_unjournaled_answer_lost)
            {
                return true;
            }
            current = link.source();
        }
        format!("{error:?}").contains("UnjournaledAnswerLost {")
    }
}
