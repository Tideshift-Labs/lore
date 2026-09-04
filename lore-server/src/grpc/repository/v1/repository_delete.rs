// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::lore::repository::v1::RepositoryDeleteRequest;
use lore_proto::lore::repository::v1::RepositoryDeleteResponse;
use lore_revision::branch;
use lore_revision::lore::RepositoryId;
use lore_revision::lore::execution_context;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::InstrumentProvider;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;

use super::record::build_repository;
use super::repository_get::repository_load_id;
use crate::domain::DomainContext;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::domain::reject_unwired_governed_operation;
use crate::grpc::ServerResultExt;
use crate::grpc::extract_authorization_header;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_user_id;
use crate::grpc::handlers::repository_delete::repository_delete_auth_resource;
use crate::util::setup_execution;

/// `lore.repository.v1.RepositoryService.RepositoryDelete` handler.
///
/// Hard-deletes the repository: clears its name → id mapping, zeroes the
/// metadata pointer, and tears down all branch metadata/HEAD pointers.
/// The response carries the last-known repository record so the caller
/// can confirm what was deleted without a separate Get.
#[tracing::instrument(name = "RepositoryDelete::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryDeleteRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    instrument_provider: &impl InstrumentProvider,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<RepositoryDeleteResponse>, Status> {
    // Captured before `into_inner` consumes the request: the domain-operation
    // headers and the verified principal both live outside the message body.
    let request_metadata = request.metadata().clone();
    let request_authorization = get_authorization_optional(request.extensions());
    let user_info = get_authorization(request.extensions());
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = extract_authorization_header(&request);
    let req = request.into_inner();

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or authorization side effect.
    if let Some(admitted) = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: &req.id,
        },
    )? {
        // BLOCKED(WP-116): no derivation for `RepositoryDeleteInput::delete_proof`.
        // Same blocker as the v0 handler, which carries the full record. Both
        // delete entry points share one coordinator method and one missing
        // artefact: a frozen `delete_proof` preimage in CR-029.
        return Err(reject_unwired_governed_operation(
            &admitted,
            "lore.repository.v1.RepositoryService/RepositoryDelete",
        ));
    }

    // TODO(mjansson): Once the authz model has read/write/admin, replace
    // the service-account bypass with a proper permission check.
    let mut bypass_protection = false;
    if let Ok(user_info) = user_info
        && user_info.is_service_account.unwrap_or_default()
    {
        bypass_protection = true;
    }

    let id: RepositoryId = Context::from(req.id).into();
    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            let (metadata, metadata_hash) = repository_load_id(repository.clone(), id, None, None)
                .await
                .map_err(|_err| Status::not_found(format!("Repository {id} not found")))?;

            let user_id = execution_context().user_id().await;
            if let Some(auth_url) = auth_url {
                repository_delete_auth_resource(auth_url, authorization, id).await?;
            } else if metadata.creator != user_id && !bypass_protection {
                info!(
                    "Repository delete refused, user {user_id} is not creator {}",
                    metadata.creator
                );
                return Err(Status::permission_denied("Not repository owner"));
            }

            repository::store_name_to_id(
                repository.clone(),
                metadata.name.as_str(),
                RepositoryId::default(),
            )
            .await
            .warn_map_err(|err| {
                Status::internal(format!("Failed to delete repository name mapping: {err}"))
            })?;

            repository::metadata_store_hash(repository.clone(), Hash::default())
                .await
                .warn_map_err(|err| {
                    Status::internal(format!("Failed to delete repository metadata: {err}"))
                })?;

            if let Ok(mut branch_stream) = branch::list(repository.clone()).await {
                let mut branch_list = vec![];
                while let Some(branch) = branch_stream.next().await {
                    branch_list.push(branch);
                }

                for branch in branch_list {
                    if let Ok(branch_metadata) = branch::metadata(repository.clone(), branch).await
                    {
                        let name = branch::name(&branch_metadata).unwrap_or_default();
                        if !name.is_empty() {
                            let _ = branch::delete_name_to_id(repository.clone(), name)
                                .await
                                .inspect_err(|err| {
                                    debug!(
                                        "Branch delete failed to remove name to ID mapping: {err}"
                                    );
                                });
                        }
                    }

                    let _ = branch::mutable_delete(repository.clone(), branch::LATEST, branch)
                        .await
                        .inspect_err(|err| {
                            debug!("Branch delete failed to remove HEAD pointer: {err}");
                        });

                    let _ = branch::mutable_delete(repository.clone(), branch::METADATA, branch)
                        .await
                        .inspect_err(|err| {
                            debug!("Branch delete failed to remove metadata pointer: {err}");
                        });
                }
            }

            info!(
                "Deleted repository {} with ID {}",
                metadata.name, repository.id
            );

            instrument_provider
                .counter("num_repositories_deleted")
                .add(1, &[]);

            Ok(Response::new(RepositoryDeleteResponse {
                repository: Some(build_repository(id, &metadata, metadata_hash)),
            }))
        })
        .await
}

#[cfg(test)]
mod tests {
    use rand::random;
    use tonic::Code;

    use super::*;
    use crate::store::test_store_create;

    struct TestInstrumentProvider;

    impl InstrumentProvider for TestInstrumentProvider {
        fn namespace(&self) -> &'static str {
            "test"
        }
    }

    fn make_request(repository_id: RepositoryId) -> Request<RepositoryDeleteRequest> {
        let id_bytes: Context = repository_id.into();
        Request::new(RepositoryDeleteRequest {
            id: bytes::Bytes::from(id_bytes),
        })
    }

    // TEST 3 (WP-116 guarded stop): confirms the ungoverned/legacy path at
    // this fenced governed-mutation call site is not blocked by the CR-029
    // gate. This file had NO test coverage of any kind before this addition.
    // `admit_at_entry`'s own `Ok(None)` behavior is already pinned generically
    // in `domain.rs`; this is the handler-specific companion. Narrow by
    // design: a repository id that was never created only reaches the first
    // statement of this handler's body (the `repository_load_id` lookup)
    // before returning `NotFound` -- it does NOT exercise the rest of the
    // handler (auth resource delete, name/metadata clearing, branch purge).
    // `NotFound` is decisive proof the request got past the gate: a gate
    // rejection here would be `Unimplemented` (an admitted-but-unwired
    // operation) or `FailedPrecondition` (carriage supplied with no domain
    // coordinator), never `NotFound`.
    #[tokio::test]
    async fn no_domain_coordinator_reaches_the_legacy_repository_lookup_not_blocked_by_the_gate() {
        let repository_id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("test stores");

        let error = LORE_CONTEXT
            .scope(execution, async move {
                handler(
                    make_request(repository_id),
                    None, /* no auth_url */
                    immutable_store,
                    mutable_store,
                    &TestInstrumentProvider,
                    None, /* no domain coordinator */
                )
                .await
            })
            .await
            .expect_err("a never-created repository must be refused by the legacy delete logic");

        assert_eq!(error.code(), Code::NotFound);
        assert!(
            error
                .message()
                .contains(&format!("Repository {repository_id} not found"))
        );
    }
}
