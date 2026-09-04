// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::RepositoryDeleteRequest;
use lore_proto::RepositoryDeleteResponse;
use lore_proto::rebac::DeleteResourceRequest;
use lore_revision::branch;
use lore_revision::lore::RepositoryId;
use lore_revision::lore::execution_context;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::InstrumentProvider;
use tokio_stream::StreamExt;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;
use tracing::warn;

use super::repository_query::repository_query_id;
use crate::authnz::common::create_request_with_authorization;
use crate::authnz::rebac::RebacApiClient;
use crate::authnz::rebac::grpc_get_rebac_client;
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
use crate::util::setup_execution;

#[tracing::instrument(name = "RepositoryDelete::handle", skip_all)]
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
        //
        // The coordinator method exists and its outbox event is classified, but
        // the tombstone row requires a 32-byte `delete_proof`
        // (`lore-postgres/src/domain/schema.rs`: a NOT NULL CHECK of exactly 32
        // bytes on any tombstoned row). CR-029 names the field three times, each
        // time only as an "attempt-compatible immutable delete proof", and
        // freezes no preimage, no field list, no serialisation, and no domain
        // separator. Nothing in either repository computes one.
        //
        // Inventing 32 bytes here is the exact failure CR-029's own MISSING-2
        // record describes for `canonical_intent_digest`: one side mints a
        // value, the other cannot reproduce it, and the divergence is silent.
        // The proof is committed into the principal-scoped receipt and returned
        // by receipt lookup, so a wrong shape becomes permanent evidence.
        //
        // Missing artefact: a frozen `delete_proof` derivation in CR-029, on
        // the same terms as its canonical-intent digest contract: one canonical
        // preimage, its exact field order and framing, and independently
        // computed golden vectors on both sides.
        return Err(reject_unwired_governed_operation(
            &admitted,
            "lore.RepositoryService/RepositoryDelete",
        ));
    }

    // TODO(mjansson): Once we have authz permission model with read/write/admin
    // this should be upgraded to check for the correct permission rather than
    // hardwired to service accounts. For now used to protect while allowing mirroring
    let mut bypass_protection = false;
    if let Ok(user_info) = user_info
        && user_info.is_service_account.unwrap_or_default()
    {
        bypass_protection = true;
    }

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    let id: RepositoryId = Context::from(req.id).into();
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            repository_delete(repository, bypass_protection, auth_url, authorization)
                .await
                .inspect_err(|err| warn!("Repository delete failed: {err}"))?;

            let num_repositories_deleted = instrument_provider.counter("num_repositories_deleted");
            num_repositories_deleted.add(1, &[]);

            Ok(Response::new(RepositoryDeleteResponse {}))
        })
        .await
}

async fn repository_delete(
    repository: Arc<RepositoryContext>,
    force: bool,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<(), Status> {
    let Ok(data) = repository_query_id(
        repository.clone(),
        repository.id,
        None, /* auth url */
        None, /* authorization */
    )
    .await
    else {
        return Err(Status::not_found("Repository does not exist"));
    };

    let metadata = repository::metadata(repository.clone(), data.metadata)
        .await
        .map_err(|_err| Status::not_found("Repository metadata not found"))?;

    let user_id = execution_context().user_id().await;

    if let Some(auth_url) = auth_url {
        // Use external auth service to authorize deletion
        repository_delete_auth_resource(auth_url, authorization, repository.id).await?;
    } else {
        // If not using external auth service, check that the current user is the creator
        if metadata.creator != user_id && !force {
            info!(
                "Repository delete refused, user {user_id} is not creator {}",
                metadata.creator
            );
            return Err(Status::permission_denied("Not repository owner"));
        }
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

    // Purge any branches
    if let Ok(mut branch_stream) = branch::list(repository.clone()).await {
        let mut branch_list = vec![];
        while let Some(branch) = branch_stream.next().await {
            branch_list.push(branch);
        }

        for branch in branch_list {
            if let Ok(branch_metadata) = branch::metadata(repository.clone(), branch).await {
                // Delete name to ID mapping
                let name = branch::name(&branch_metadata).unwrap_or_default();
                if !name.is_empty() {
                    let _ = branch::delete_name_to_id(repository.clone(), name)
                        .await
                        .inspect_err(|err| {
                            debug!("Branch delete failed to remove name to ID mapping: {err}");
                        });
                }
            }

            // Delete the latest pointer from mutable store
            let _ = branch::mutable_delete(repository.clone(), branch::LATEST, branch)
                .await
                .inspect_err(|err| {
                    debug!("Branch delete failed to remove HEAD pointer: {err}");
                });

            // Delete the metadata pointer from mutable store
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

    Ok(())
}

pub(crate) async fn repository_delete_auth_resource(
    auth_url: String,
    authorization: Option<String>,
    repository_id: RepositoryId,
) -> Result<(), Status> {
    info!("Repository delete auth resource for {}", repository_id,);

    let mut client = grpc_get_rebac_client(auth_url).await?;
    let request = create_request_with_authorization(
        DeleteResourceRequest {
            resource_id: format!("urc-{repository_id}"),
        },
        authorization,
    )?;

    client.delete_resource(request).await.warn_map_err(|err| {
        if err.code() == Code::PermissionDenied {
            return Status::permission_denied("Delete resource denied");
        } else if err.code() == Code::Unauthenticated {
            return Status::unauthenticated("Delete resource failed - unauthenticated");
        }
        Status::internal(format!("Failed to call auth delete_resource: {err}"))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::random;

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
    // statement of the legacy `repository_delete` logic (the
    // `repository_query_id` lookup) before returning `NotFound` -- it does
    // NOT exercise the rest of that function (name/metadata clearing, branch
    // purge). `NotFound` is decisive proof the request got past the gate: a
    // gate rejection here would be `Unimplemented` (an admitted-but-unwired
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
        assert!(error.message().contains("Repository does not exist"));
    }
}
