// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_proto::BranchDeleteRequest;
use lore_proto::BranchDeleteResponse;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::notification::NotificationSender;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::tracing::fields::BRANCH_ID;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::domain::DomainContext;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::domain::reject_unwired_governed_operation;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::hook_error_to_status;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::util::setup_execution;

#[tracing::instrument(name = "BranchDelete::handle", skip_all)]
pub async fn handler(
    request: Request<BranchDeleteRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    notification_sender: Arc<dyn NotificationSender>,
    hook_dispatcher: &HookDispatcher,
    instrument_provider: &impl InstrumentProvider,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchDeleteResponse>, Status> {
    let repository_id = get_repository(request.metadata())?;
    // Captured before `into_inner` consumes the request: the domain-operation
    // headers and the verified principal both live outside the message body.
    let request_metadata = request.metadata().clone();
    let request_authorization = get_authorization_optional(request.extensions());
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let req = request.into_inner();
    let branch = BranchId::from(req.branch);

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or side effect. This site had
    // no gate at all until now (WP-119 writer inventory B4), so carriage was
    // silently ignored and a caller that asked for governed semantics got
    // today's unsynchronised single-key write while believing its operation had
    // been admitted and receipted. Refusing is the strictly better answer.
    if let Some(admitted) = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: repository_id.data(),
        },
    )? {
        // BLOCKED(WP-116): branch delete_proof derivation unfrozen in CR-029,
        // and CR-029 freezes no `CanonicalIntent::BranchDelete` family.
        //
        // Everything else this site needs is built and shared with the v1 site:
        // `crate::domain::GovernedBranchDelete` carries the one projection row
        // (`BranchDeletePublication::projection`, the single live-name key
        // `branch::delete` retires), the one classified `branch.deleted` event
        // CR-032 assigns to a branch tombstone, the `BranchDeleteInput`
        // carriage, the coordinator call, and the outcome mapping.
        // `PostgresDomainStore::branch_delete` is real and complete.
        //
        // Two inputs have no derivation, and the second is why the refusal is
        // HERE rather than at the seam:
        //
        // 1. The 32-byte tombstone proof `lore_domain_branches_tombstone_evidence`
        //    requires on any tombstoned branch row. CR-029 names it only as an
        //    "attempt-compatible immutable tombstone proof" and freezes no
        //    preimage, field list, serialisation, or domain separator. It is
        //    committed into the principal-scoped receipt and returned by receipt
        //    lookup, so a minted shape becomes permanent evidence.
        //    `GovernedBranchDelete::commit` fails closed on it.
        // 2. There is no `CanonicalIntent::BranchDelete`. CR-029's
        //    canonical-intent contract freezes six families;
        //    `crate::domain_intent` defines those six and the platform's
        //    `repository-operation-intent.ts` defines the same six.
        //    `GovernedBranchDelete::prepare` needs a digest this handler cannot
        //    derive, and a Lore-side seventh family would fail every admission
        //    the platform offered it. So this site cannot even reach the seam's
        //    own fence, which is why it must refuse at entry.
        //
        // Refusing here also keeps a delete that will certainly refuse from
        // first dispatching the pre-hook and the `branch_deleted` notification.
        //
        // Missing artefacts: a frozen branch `delete_proof` derivation and a
        // frozen seventh canonical-intent family, both in CR-029 and both on the
        // same terms as its existing canonical-intent digest contract: one
        // canonical preimage, its exact field order and framing, and
        // independently computed golden vectors on both sides.
        return Err(reject_unwired_governed_operation(
            &admitted,
            "lore.RevisionService/BranchDelete",
        ));
    }

    debug!({BRANCH_ID} = %branch, "Handling branch delete");

    let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));
    LORE_CONTEXT
        .scope(execution, async move {
            let hook_ctx = HookContext::builder()
                .correlation_id(correlation_id)
                .hook_point(HookPoint::BranchDelete)
                .repository(repository_id)
                .user(user_id)
                .branch(branch)
                .build();

            hook_dispatcher
                .dispatch_pre(HookPoint::BranchDelete, &hook_ctx)
                .map_err(hook_error_to_status)?;

            match branch::delete(repository, branch).await {
                Ok(_) => {
                    debug!({BRANCH_ID} = %branch, "Branch deleted");
                    let num_branches_deleted = instrument_provider.counter("num_branches_deleted");
                    num_branches_deleted.add(1, &[]);

                    notification_sender
                        .branch_deleted(repository_id, branch)
                        .await;

                    hook_dispatcher.spawn_post(HookPoint::BranchDelete, hook_ctx);

                    Ok(Response::new(BranchDeleteResponse {}))
                }
                Err(err) if err.is_branch_not_found() => {
                    info!({BRANCH_ID} = %branch, "Failed to delete branch - does not exist");
                    Ok(Response::new(BranchDeleteResponse {}))
                }
                Err(err) if err.is_delete_protected() => {
                    info!({BRANCH_ID} = %branch, "Failed to delete branch - DeleteProtected");
                    Err(Status::failed_precondition("Branch is delete protected"))
                }
                Err(err) => {
                    warn!({BRANCH_ID} = %branch, error = ?err, "Failed to delete branch");
                    Err(Status::internal(err.to_string()))
                }
            }
        })
        .await
}

#[cfg(test)]
mod test {

    use std::sync::Arc;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::BranchPoint;
    use lore_base::types::Hash;
    use lore_revision::branch;
    use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
    use lore_revision::branch::protect;
    use lore_revision::lore::RepositoryId;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::state;
    use lore_transport::grpc::REPOSITORY_ID_KEY;
    use mockall::predicate::eq;
    use opentelemetry::KeyValue;
    use rand::random;
    use tonic::Request;

    use super::*;
    use crate::grpc::get_write_token;
    use crate::grpc::handlers::branch_push;
    use crate::hooks::HookDispatcher;
    use crate::notification::testing::MockNotificationSender;
    use crate::store::test_store_create;

    struct TestInstrumentProvider {}

    impl InstrumentProvider for TestInstrumentProvider {
        fn namespace(&self) -> &'static str {
            "test"
        }
        fn labels(&self) -> &[KeyValue] {
            &[]
        }
    }

    /// The entry gate refuses before the legacy body runs, not after it.
    ///
    /// The discriminating assertions are both negative, and both would pass
    /// vacuously if written any other way:
    ///
    /// * `MockNotificationSender::new()` carries NO expectation, and mockall
    ///   panics on an unexpected call. That IS the proof that the refusal
    ///   precedes `branch_deleted`, which is the side effect the gate exists to
    ///   prevent. Setting an explicit zero-times expectation would say the same
    ///   thing less loudly.
    /// * The branch does not exist. Without the gate this handler treats a
    ///   missing branch as SUCCESS (`is_branch_not_found` returns
    ///   `Ok(BranchDeleteResponse {})`), so a regression that removed the gate
    ///   would return `Ok` and fail `expect_err` rather than quietly returning a
    ///   different error code.
    ///
    /// Enforcement with no carriage is `InvalidArgument` from the shared gate,
    /// not the `Unimplemented` a carriage-bearing request gets: this pins that
    /// the cell refuses at entry at all, which is the property that was missing
    /// entirely before WP-119 (writer inventory B4).
    #[tokio::test]
    #[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
    async fn enforcing_cell_rejects_before_legacy_branch_delete_body() {
        let Some(domain) = crate::domain::test_support::configured_enforcing_context().await else {
            panic!("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");
        };
        let repository = random::<RepositoryId>();
        let branch = BranchId::from(uuid::Uuid::now_v7());
        let (immutable_store, mutable_store, _) = test_store_create().await.expect("test stores");
        let notification_sender = Arc::new(MockNotificationSender::new());
        let instrument_provider = TestInstrumentProvider {};
        let hook_dispatcher = HookDispatcher::empty();

        let mut request = Request::new(BranchDeleteRequest {
            branch: branch.into(),
        });
        request.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );

        let error = handler(
            request,
            immutable_store,
            mutable_store,
            notification_sender,
            &hook_dispatcher,
            &instrument_provider,
            Some(&domain),
        )
        .await
        .expect_err("enforcement must reject missing operation carriage at entry");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    async fn create_test_branch(repository_context: Arc<RepositoryContext>, branch: BranchId) {
        let write_token = get_write_token();
        let main = lore_revision::branch::create(
            repository_context.clone(),
            &write_token,
            BranchId::from(uuid::Uuid::now_v7()),
            branch::DEFAULT_DEFAULT_NAME,
            branch::default_category(),
            "test-creator",
            1,
            vec![],
            false,
            false,
        )
        .await
        .expect("Could not create main branch");

        // create a revision in main to branch from
        let state = Arc::new(state::State::new());
        state.set_parent_self(Hash::default());
        state.set_revision_number(1);
        let state_hash = state
            .serialize(repository_context.clone(), &write_token)
            .await
            .expect("Failed to serialize state");

        let head = branch_push::push(
            repository_context.clone(),
            main,
            state_hash,
            true,
            true,
            false,
            DEFAULT_HISTORY_STEP_SIZE,
            crate::grpc::server::RevisionListAcceleration::default(),
        )
        .await
        .expect("Failed to push head revision")
        .revision;

        lore_revision::branch::create(
            repository_context.clone(),
            &write_token,
            branch,
            "test-name",
            branch::personal_category(),
            "BranchCreator",
            12345,
            vec![BranchPoint {
                branch: main,
                revision: head,
            }],
            false,
            false,
        )
        .await
        .expect("Could not create test branch");
    }

    #[tokio::test]
    async fn sends_delete_notification_for_deleted_branch() {
        let repository = random::<RepositoryId>();
        let branch = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let mut notification_sender = MockNotificationSender::new();
        notification_sender
            .expect_branch_deleted()
            .with(eq(repository), eq(branch))
            .return_once(|_, _| ());
        let notification_sender = Arc::new(notification_sender);
        let instrument_provider = TestInstrumentProvider {};

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));

            create_test_branch(repository_context.clone(), branch).await;

            let mut request = Request::new(BranchDeleteRequest {
                branch: branch.into(),
            });
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let hook_dispatcher = HookDispatcher::empty();
            handler(
                request,
                immutable_store.clone(),
                mutable_store.clone(),
                notification_sender.clone(),
                &hook_dispatcher,
                &instrument_provider,
                None,
            )
            .await
            .expect("Request failed");
        }))
        .await;
    }

    #[tokio::test]
    async fn no_delete_notification_for_branch_not_exists() {
        let repository = random::<RepositoryId>();

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        // no notifications sent, so no expectations required
        let notification_sender = Arc::new(MockNotificationSender::new());
        let instrument_provider = TestInstrumentProvider {};

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let mut request = Request::new(BranchDeleteRequest {
                branch: BranchId::from(uuid::Uuid::now_v7()).into(),
            });
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let hook_dispatcher = HookDispatcher::empty();
            handler(
                request,
                immutable_store.clone(),
                mutable_store.clone(),
                notification_sender.clone(),
                &hook_dispatcher,
                &instrument_provider,
                None,
            )
            .await
            .expect("Request failed");
        }))
        .await;
    }

    #[tokio::test]
    async fn no_delete_notification_for_branch_delete_errors() {
        let repository = random::<RepositoryId>();
        let branch = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        // no notifications sent, so no expectations required
        let notification_sender = Arc::new(MockNotificationSender::new());
        let instrument_provider = TestInstrumentProvider {};

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));

            create_test_branch(repository_context.clone(), branch).await;
            // protecting the branch will prevent it from deletion
            protect(repository_context.clone(), branch)
                .await
                .expect("should protect");

            let mut request = Request::new(BranchDeleteRequest {
                branch: branch.into(),
            });
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let hook_dispatcher = HookDispatcher::empty();
            let response = handler(
                request,
                immutable_store.clone(),
                mutable_store.clone(),
                notification_sender.clone(),
                &hook_dispatcher,
                &instrument_provider,
                None,
            )
            .await
            .unwrap_err();

            assert_eq!(response.code(), tonic::Code::FailedPrecondition);
        }))
        .await;
    }
}
