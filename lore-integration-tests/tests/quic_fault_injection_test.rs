// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-124 follow-up (d): the server-side QUIC fault seam (`lore_server::quic::faults`), live.
//
// [SERVER]-class (the seam is a `failure_generator`-only module of `lore-server`), exercised
// through the stock `lore-transport` client against the real strict `StorageServiceV4` that the
// managed-write harness (`quic_managed_write_support`) already serves in process.
//
// What this proves: with `answer-loss` armed for a repository, a declared managed `Put` is applied
// by the store and its answer is withheld; the client ends the write as `UnjournaledAnswerLost`
// (never an unknown outcome, never resent: exactly one `Put` on the wire); a disarm releases the
// held answer; and the next managed `Put` on the same session is admitted.
//
// Needs the `quic_faults` feature (`lore-server/failure_generator`). The hooks read the process-wide
// registry, so the case selects by a random repository and always disarms; no other case in this
// binary arms. The client's answer bound is its 60 s managed idle bound, so this case takes about a
// minute.
#[cfg(all(test, feature = "integration_tests", feature = "quic_faults"))]
mod quic_fault_injection_tests {
    use std::time::Duration;

    use lore_revision::fragment;
    use lore_revision::lore::RepositoryId;
    use lore_server::quic::faults::ArmRequest;
    use lore_server::quic::faults::Fault;
    use lore_server::quic::faults::WriteVerb;
    use lore_server::quic::faults::registry;
    use lore_transport::is_unjournaled_answer_lost;
    use lore_transport::quic::storage_service::Command;
    use lore_transport::with_caller_operation;
    use rand::random;

    use crate::quic_managed_write_support::TestResult;
    use crate::quic_managed_write_support::cell;
    use crate::quic_managed_write_support::connect;
    use crate::quic_managed_write_support::eventually;
    use crate::quic_managed_write_support::in_context;
    use crate::quic_managed_write_support::managed;
    use crate::quic_managed_write_support::stored;

    /// Disarms on drop, so a failed assertion never leaves the process-wide registry armed.
    struct Disarm;

    impl Drop for Disarm {
        fn drop(&mut self) {
            registry().disarm();
        }
    }

    #[tokio::test]
    async fn answer_loss_on_a_declared_managed_put_is_an_unjournaled_loss_with_one_store_write()
    -> TestResult {
        in_context(async {
            let _disarm = Disarm;
            let cell = cell(None, None, None).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await?;
            let session = connection.session(partition, "fault-answer-loss").await?;
            let (fragment, address, payload) = fragment::generate_random();
            let (scope, journal) = managed(partition);

            registry()
                .arm(ArmRequest {
                    fault: Fault::AnswerLoss,
                    repository: partition.to_string(),
                    verb: Some(WriteVerb::Put),
                })
                .map_err(|error| format!("arming the fault: {error:?}"))?;

            let error = tokio::time::timeout(
                Duration::from_secs(150),
                with_caller_operation(
                    scope.clone(),
                    session.put(address, fragment, Some(payload.clone())),
                ),
            )
            .await
            .expect("a withheld answer must end the Put, not hang it")
            .expect_err("the Put's answer was withheld, so the call cannot succeed");

            assert!(
                is_unjournaled_answer_lost(&error),
                "a withheld managed fragment-write answer is an unjournaled loss: {error:?}"
            );
            assert!(!error.is_outcome_unknown(), "{error:?}");
            assert_eq!(scope.declared_session_count(), 1, "the Put ran declared");
            let wire = cell.probe.wire();
            assert_eq!(
                cell.probe.count_opcode(Command::Put),
                1,
                "the client sent exactly one Put: {wire:?}"
            );
            assert!(
                stored(&cell.stores, partition, address).await,
                "the answer was withheld only after the real write"
            );
            assert_eq!(journal.records.load(std::sync::atomic::Ordering::SeqCst), 0);

            let state = registry().state();
            assert!(state.armed.is_none(), "the claim spent the arm");
            assert_eq!(state.fired.len(), 1);
            assert_eq!(state.fired[0].fault, Fault::AnswerLoss);
            assert!(state.fired[0].store_accepted);
            assert_eq!(
                state.fired[0].address.as_deref(),
                Some(address.to_string().as_str())
            );

            // A disarm releases the held answer; nothing stays held.
            registry().disarm();
            eventually("the held answer to be released", || {
                registry().state().held == 0
            })
            .await;

            // The next managed Put on the same session is admitted and is not faulted.
            let (next_fragment, next_address, next_payload) = fragment::generate_random();
            let (next_scope, _next_journal) = managed(partition);
            with_caller_operation(
                next_scope.clone(),
                session.put(next_address, next_fragment, Some(next_payload.clone())),
            )
            .await?;
            assert!(stored(&cell.stores, partition, next_address).await);
            assert_eq!(
                registry().state().fired.len(),
                1,
                "a spent arm does not fire again"
            );
            let (_, read) = session.get(&next_address).await?;
            assert_eq!(read, next_payload);
            Ok(())
        })
        .await
    }
}
