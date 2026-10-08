// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::outbox::builders as outbox_builders;
use lore_proto::lore::revision::v1::BranchMetadataSetRequest;
use lore_proto::lore::revision::v1::BranchMetadataSetResponse;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::metadata::Metadata;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::tracing::fields::BRANCH_ID;
use lore_telemetry::tracing::fields::METADATA;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::domain::DomainContext;
use crate::domain::GovernedMetadataCas;
use crate::domain::GovernedScope;
use crate::domain::MetadataCasFamily;
use crate::domain::MetadataCasOutcome;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::get_write_token;
use crate::grpc::handlers::branch_metadata_set::validate_binary_blobs;
use crate::grpc::handlers::branch_metadata_set::validate_read_only_fields;
use crate::grpc::require_permission;
use crate::grpc::warn_error_to_status;
use crate::util::setup_execution;

/// `lore.revision.v1.RevisionService.BranchMetadataSet` handler.
///
/// Compare-and-swap update of a branch's metadata pointer. CAS miss is
/// signalled in-band: the response always carries the current pointer
/// after the call. On hit, `response.metadata == request.updated`; on
/// miss, `response.metadata` is the unchanged prior value, and the
/// caller compares against `request.updated` to detect the miss.
///
/// `protect` remains writable through this RPC (it is not in the
/// read-only key set) so clients can continue to toggle branch
/// protection without dedicated protect/unprotect RPCs.
#[tracing::instrument(name = "BranchMetadataSet::v1::handle", skip_all)]
pub async fn handler(
    request: Request<BranchMetadataSetRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    enforce_write_permission: bool,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchMetadataSetResponse>, Status> {
    let request_metadata = request.metadata().clone();
    let request_authorization = crate::grpc::get_authorization_optional(request.extensions());
    let repository_id = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    // Capture the auth token before the request is consumed; the
    // PROTECT-set gate below needs it once both metadata blobs are
    // deserialized.
    let extensions = request.extensions().clone();
    let req = request.into_inner();

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or authorization side effect.
    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: repository_id.data(),
        },
    )?;

    let branch_id = BranchId::from(req.id);
    if branch_id == BranchId::default() {
        return Err(Status::invalid_argument("Branch id must be non-zero"));
    }

    // Recomputed from the exact validated wire values, never taken from the
    // body. v0 and v1 of this CAS share one frozen intent family, so identical
    // values must produce identical bytes on both entry points.
    //
    // After the empty/default check, per INTENT-02-LORE; see the v0 repository
    // handler for the full reasoning.
    let governed = match admitted {
        Some(admitted) => {
            let digest = canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: repository_id.data(),
                branch_id: branch_id.as_ref(),
                expected_hash: &req.expected,
                new_hash: &req.updated,
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            GovernedMetadataCas::prepare(
                domain_context,
                Some(admitted),
                MetadataCasFamily::Branch,
                digest,
            )
            .await?
        }
        None => None,
    };

    let expected: Hash = req.expected.into();
    let updated: Hash = req.updated.into();

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            debug!(
                {BRANCH_ID} = %branch_id,
                expected = %expected,
                updated = %updated,
                "Branch metadata CAS",
            );

            // Reject writes to branches that have no metadata pointer
            // at all (never created). Deleted branches keep their
            // metadata blob and pass this check.
            branch::metadata_hash(repository.clone(), branch_id)
                .await
                .filter_slow_down()?
                .map_err(|err| {
                    info!({BRANCH_ID} = %branch_id, ?err, "Branch metadata not found");
                    Status::not_found(format!("Branch {branch_id} not found"))
                })?;

            // Caller-supplied `expected` is treated as authoritative for
            // the validation pass: it lets the server check that the
            // proposed transformation is well-formed even if the
            // underlying state has moved. The CAS itself ensures
            // atomicity against the actual current pointer.
            let current_metadata = if expected.is_zero() {
                Metadata::new()
            } else {
                Metadata::deserialize(repository.clone(), expected)
                    .await
                    .filter_slow_down()?
                    .map_err(|err| {
                        warn_error_to_status(&err, |err| {
                            Status::invalid_argument(format!(
                                "failed to deserialize expected metadata: {err}"
                            ))
                        })
                    })?
            };

            let proposed_metadata = Metadata::deserialize(repository.clone(), updated)
                .await
                .filter_slow_down()?
                .map_err(|err| {
                    warn_error_to_status(&err, |err| {
                        Status::invalid_argument(format!(
                            "failed to deserialize updated metadata: {err}"
                        ))
                    })
                })?;

            // Enforce write authorization. Toggling the PROTECT bit
            // requires `admin` (branch protection is an admin act); any
            // other metadata write requires `write`. No-op when auth is
            // OFF or the flag is disabled.
            let protect_changed = current_metadata
                .get_bool(branch::PROTECT)
                .unwrap_or_default()
                != proposed_metadata
                    .get_bool(branch::PROTECT)
                    .unwrap_or_default();
            let required_permission = if protect_changed { "admin" } else { "write" };
            require_permission(
                &extensions,
                repository_id,
                required_permission,
                enforce_write_permission,
            )?;

            validate_read_only_fields(&current_metadata, &proposed_metadata)?;
            validate_binary_blobs(repository.clone(), &proposed_metadata).await?;

            let (metadata_key, key_type) = branch::mutable_key(
                repository::SALT_LORE,
                branch::METADATA,
                repository_id,
                branch_id,
            );
            // The governed path swaps the pointer, writes the same projection
            // row, and appends the classified event in one transaction. The
            // classification is not always `branch.metadata_changed`: the
            // PROTECT bit travels inside this same CAS, and CR-032 pins
            // `branch.protection_changed` as its own kind. `protect_changed` is
            // already computed above for the admin-permission gate, so the two
            // decisions cannot drift apart.
            //
            // PIN(WP-116): a CAS that moves the PROTECT bit AND other metadata
            // in one write is classified as the protection change, because that
            // is the transition with the stricter authorization and the named
            // consumer. The pinned set's second open question is whether these
            // two kinds stay distinct at all; if they merge, this branch
            // collapses rather than changing meaning.
            let previous = if let Some(governed) = &governed {
                let event = match governed.outbox_cell_id() {
                    Some(cell_id) => {
                        // Read before the transaction, so the name and tip
                        // are a preflight observation. They go in the
                        // payload only; the aggregate version is resolved
                        // by the coordinator from what it commits.
                        let branch = governed
                            .branch_snapshot(repository_id.data(), branch_id.as_ref())
                            .await?
                            .ok_or_else(|| {
                                Status::not_found(format!("Branch {branch_id} not found"))
                            })?;
                        let built = if protect_changed {
                            outbox_builders::branch_protection_changed(
                                cell_id,
                                repository_id.data(),
                                branch_id.as_ref(),
                                &branch.name,
                                &branch.latest_hash,
                                expected.as_ref(),
                                updated.as_ref(),
                                proposed_metadata
                                    .get_bool(branch::PROTECT)
                                    .unwrap_or_default(),
                            )
                        } else {
                            outbox_builders::branch_metadata_changed(
                                cell_id,
                                repository_id.data(),
                                branch_id.as_ref(),
                                &branch.name,
                                &branch.latest_hash,
                                expected.as_ref(),
                                updated.as_ref(),
                            )
                        };
                        Some(
                            built
                                .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                        )
                    }
                    None => None,
                };
                let projection = ProjectionWrite {
                    partition: repository_id.data().to_vec(),
                    key_type: key_type as i16,
                    key: metadata_key.as_ref().to_vec(),
                    value: Some(updated.as_ref().to_vec()),
                };
                match governed
                    .commit(
                        repository_id.data(),
                        Some(branch_id.as_ref()),
                        expected.as_ref(),
                        updated.as_ref(),
                        projection,
                        event,
                    )
                    .await?
                {
                    MetadataCasOutcome::Applied => expected,
                    MetadataCasOutcome::Lost(observed) => Hash::from(observed.as_slice()),
                }
            } else {
                let write_token = get_write_token();
                repository
                    .write_mutable_store(&write_token)
                    .compare_and_swap(repository_id, metadata_key, expected, updated, key_type)
                    .await
                    .filter_slow_down()?
                    .map_err(|err| {
                        warn!({BRANCH_ID} = %branch_id, ?err, "Branch metadata CAS failed");
                        warn_error_to_status(&err, |err| {
                            Status::internal(format!("failed to update branch metadata: {err}"))
                        })
                    })?
            };

            let metadata = if previous == expected {
                updated
            } else {
                previous
            };

            debug!(
                {BRANCH_ID} = %branch_id,
                {METADATA} = %metadata,
                hit = previous == expected,
                "Branch metadata CAS response",
            );

            Ok(Response::new(BranchMetadataSetResponse {
                metadata: metadata.into(),
            }))
        })
        .await
}
